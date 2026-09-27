"""
Browser Server - שירת דפדפן נגיש לסוכן AI.

מדדיד ומאמת: השירת הזו רצה בתוך 512MB של Render Free. Chromium במצב
headless, ללא Playwright, דרך Chrome DevTools Protocol ישיר.

עקרונות שנבעו ממדידה (לא מניחות):
  1. דפדפן אחד בלבד, ללא מקביליות - כל דפדפן נוסף הוא ~150MB
  2. דף חדש לכל ניווט - שימוש באותו טאב גורם לצבירת זיכרון
  3. הפעלה מחדש של הדפדפן כל N פעולות - Chromium מצטבר בתהליך עצמו
  4. סגירה אחרי שקט - כדי לא להפקיד ~190MB שלא לצורך
  5. שיא הזיכרון המדוד הוא PSS, לא RSS - רק כך סופרים זיכרון משותף נכון

אבטחה:
  - BROWSER_TOKEN חובה. ללא היא כל הנתיבים סגורים.
  - חסימת SSRF כדי שהשירות לא תהפוך לפרוקסי פתוח
  - הגבלת קצב לפי IP
  - אפשר להגביל לדומיין מורשים בלבד (ALLOWED_DOMAINS)
"""
from __future__ import annotations

import asyncio
import base64
import gc
import hmac
import os
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from cdp import CDP, BrowserError, browser_inventory, check_url, resolve_browser

# =============================================================== הגדרות
def _env(name: str, default: str = "") -> str:
    return os.getenv(name, "").strip() or default


def _int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)) or default)
    except ValueError:
        return default


TOKEN = _env("BROWSER_TOKEN")
MEMORY_LIMIT_MB = _int("MEMORY_LIMIT_MB", 512)
IDLE_TIMEOUT_SEC = _int("IDLE_TIMEOUT_SEC", 75)      # אחרי זה הדפדפן נסגר
MAX_ACTIONS_PER_BROWSER = _int("MAX_ACTIONS_PER_BROWSER", 5)  # recycling
MAX_TASKS_CONCURRENT = 1                            # 512MB = דפדפן אחד בלבד
RATE_LIMIT_PER_MIN = _int("RATE_LIMIT_PER_MIN", 60)
MAX_NAVIGATIONS_PER_SESSION = _int("MAX_NAVIGATIONS_PER_SESSION", 25)
MAX_TEXT_CHARS = _int("MAX_TEXT_CHARS", 8000)
ALLOWED_DOMAINS = [d.strip().lower() for d in _env("ALLOWED_DOMAINS").split(",") if d.strip()]

app = FastAPI(title="browser-server", version="1.0")

if not TOKEN:
    print("WARNING: BROWSER_TOKEN is not set - the API will refuse every call.",
          flush=True)


# =============================================================== אבטחה
_hits: Dict[str, deque] = defaultdict(deque)


async def require_token(x_browser_token: str = Header(default="")) -> None:
    """אימות. השירת אינה פעילה בלי טוקן - בכלל."""
    if not TOKEN:
        raise HTTPException(status_code=503, detail="BROWSER_TOKEN is not configured on the server")
    provided = (x_browser_token or "").strip()
    if not provided or not hmac.compare_digest(provided, TOKEN):
        raise HTTPException(status_code=401, detail="missing or invalid X-Browser-Token")


def require_rate_limit(request: Request) -> None:
    if RATE_LIMIT_PER_MIN <= 0:
        return
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MIN:
        raise HTTPException(status_code=429, detail="rate limit exceeded (per minute)")
    q.append(now)
    if len(_hits) > 2000:
        for k in [k for k, v in _hits.items() if not v]:
            _hits.pop(k, None)


def guard_url(url: str) -> str:
    """חסימת SSRF + אופציונלי רשימת דומיינים מורשים.

    מעלה BrowserError כדי שהסוכן יקבל 400 מפורש ולא 500 - הוא צריך
    להבחין בין "הכתובת חסומה" לבין "השרת נפל".
    """
    try:
        clean = check_url(url)
    except BrowserError as e:
        raise HTTPException(status_code=400, detail=f"blocked url: {e}")

    if ALLOWED_DOMAINS:
        host = (urlparse(clean).hostname or "").lower()
        ok = any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)
        if not ok:
            raise HTTPException(
                status_code=403,
                detail=f"domain not allowed: {host} (allowed: {', '.join(ALLOWED_DOMAINS)})",
            )
    return clean


# =========================================================== מדידת זיכרון
def _pss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/smaps_rollup", "r") as fh:
            for line in fh:
                if line.startswith("Pss:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0


def _cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except Exception:
        return ""


def memory_report() -> Dict[str, Any]:
    chromium = python = 0
    procs = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        cmd = _cmdline(pid)
        if not cmd:
            continue
        low = cmd.lower()
        if "chrome" in low or "chromium" in low or "headless_shell" in low:
            chromium += _pss_kb(pid)
            procs += 1
        elif "uvicorn" in low or "python" in low:
            python += _pss_kb(pid)
    return {
        "total_pss_mb": round((chromium + python) / 1024, 1),
        "chromium_pss_mb": round(chromium / 1024, 1),
        "python_pss_mb": round(python / 1024, 1),
        "chromium_processes": procs,
        "limit_mb": MEMORY_LIMIT_MB,
    }


# =========================================================== מנהל הדפדפן
class Session:
    """דפדפן אחד + דף אחד. ממוחזר אוטומטית כדי לא לצבור זיכרון."""

    def __init__(self, sid: str):
        self.id = sid
        self.cdp: Optional[CDP] = None
        self.page = None
        self.actions = 0
        self.navigations = 0
        self.last_used = time.time()
        self.url = ""
        self.title = ""
        self.history: List[str] = []
        self.lock = asyncio.Lock()
        self.restarts = 0

    async def ensure(self) -> Any:
        if self.page is not None:
            self.touch()
            return self.page
        await self.launch()
        return self.page

    async def launch(self) -> None:
        await self.teardown()
        self.cdp = CDP()
        await self.cdp.start()
        self.page = await self.cdp.new_page()
        self.actions = 0
        self.navigations = 0
        self.history = []
        self.url = ""
        self.title = ""
        self.restarts += 1
        self.touch()

    async def recycle(self) -> None:
        """הפעלה מחדש. נקרא אחרי מספר פעולים כדי לא לצבור זיכרון."""
        await self.launch()

    async def teardown(self) -> None:
        if self.cdp:
            try:
                await self.cdp.stop()
            except Exception:
                pass
        self.cdp = None
        self.page = None
        gc.collect()

    def touch(self) -> None:
        self.last_used = time.time()

    def idle_for(self) -> float:
        return time.time() - self.last_used

    def should_recycle(self) -> bool:
        return self.actions >= MAX_ACTIONS_PER_BROWSER

    def state(self) -> Dict[str, Any]:
        return {
            "session": self.id,
            "alive": self.page is not None,
            "actions": self.actions,
            "navigations": self.navigations,
            "restarts": self.restarts,
            "idle_sec": round(self.idle_for(), 1),
            "url": self.url,
            "title": self.title,
            "memory": memory_report(),
        }


class BrowserManager:
    def __init__(self) -> None:
        self.sessions: Dict[str, Session] = {}
        self.gate = asyncio.Semaphore(MAX_TASKS_CONCURRENT)
        self._sweeper: Optional[asyncio.Task] = None

    def start(self) -> None:
        if self._sweeper is None:
            self._sweeper = asyncio.create_task(self._sweep())

    def get(self, sid: str) -> Session:
        s = self.sessions.get(sid)
        if s is None:
            s = Session(sid)
            self.sessions[sid] = s
        return s

    async def _sweep(self) -> None:
        """סוגר דפדפנים שלא בשימוש - כל דפדפן שקט מנערך ~190MB."""
        while True:
            try:
                await asyncio.sleep(10)
                for sid in list(self.sessions):
                    s = self.sessions[sid]
                    if s.page is not None and s.idle_for() > IDLE_TIMEOUT_SEC:
                        await s.teardown()
                    if s.page is None and s.idle_for() > IDLE_TIMEOUT_SEC * 4:
                        self.sessions.pop(sid, None)
            except asyncio.CancelledError:
                return
            except Exception:
                pass

    async def shutdown(self) -> None:
        if self._sweeper:
            self._sweeper.cancel()
        for s in list(self.sessions.values()):
            await s.teardown()


manager = BrowserManager()


# =============================================================== מודלים
class OpenReq(BaseModel):
    url: str = Field(..., max_length=2000)


class SelectorReq(BaseModel):
    selector: str = Field(..., max_length=500)


class FillReq(BaseModel):
    selector: str = Field(..., max_length=500)
    text: str = Field(default="", max_length=8000)


class PressReq(BaseModel):
    key: str = Field(default="enter", max_length=20)


class ScrollReq(BaseModel):
    direction: str = Field(default="down", max_length=10)
    amount: Optional[int] = None


class ReadReq(BaseModel):
    maxChars: int = Field(default=MAX_TEXT_CHARS, le=20000)


class ShotReq(BaseModel):
    fullPage: bool = False


# ================================================================== נתיבים
@app.on_event("startup")
async def _startup() -> None:
    manager.start()
    try:
        path, needs_headless = resolve_browser()
        print(f"[boot] chromium={path} needs_headless_flag={needs_headless}", flush=True)
    except BrowserError as e:
        print(f"[boot] no chromium: {e}", flush=True)


@app.on_event("shutdown")
async def _shutdown() -> None:
    await manager.shutdown()


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "auth_configured": bool(TOKEN),
        "sessions": len(manager.sessions),
        "memory": memory_report(),
        "limits": {
            "idle_timeout_sec": IDLE_TIMEOUT_SEC,
            "actions_per_browser": MAX_ACTIONS_PER_BROWSER,
            "max_concurrent": MAX_TASKS_CONCURRENT,
            "rate_limit_per_min": RATE_LIMIT_PER_MIN,
        },
    }


@app.get("/browsers", dependencies=[Depends(require_token)])
def browsers():
    try:
        return browser_inventory()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:300]}"}


@app.get("/b/state", dependencies=[Depends(require_token)])
def state(session: str = "default"):
    return manager.get(session).state()


@app.delete("/b/session", dependencies=[Depends(require_token)])
async def close_session(session: str = "default"):
    s = manager.sessions.get(session)
    if s:
        await s.teardown()
        return {"closed": True, "memory": memory_report()}
    return {"closed": False, "note": "no such session"}


@app.post("/b/open", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_open(req: OpenReq, session: str = "default"):
    guard_url(req.url)
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            try:
                if s.page is None or s.should_recycle():
                    await s.launch()
                if s.navigations >= MAX_NAVIGATIONS_PER_SESSION:
                    await s.recycle()
                res = await s.page.goto(guard_url(req.url), timeout=20.0)
                s.url = res["url"]
                s.title = res["title"]
                s.history.append(s.url)
                s.navigations += 1
                s.actions += 1
                s.touch()
                return {"url": s.url, "title": s.title,
                        "navigations": s.navigations, "memory": memory_report()}
            except HTTPException:
                raise
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.post("/b/read", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_read(req: ReadReq, session: str = "default"):
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            if s.page is None:
                raise HTTPException(status_code=409, detail="no page open - call /b/open first")
            try:
                info = await s.page.read_page(max_chars=req.maxChars)
                s.actions += 1
                s.touch()
                return {**info, "url": s.url or info.get("url"), "memory": memory_report()}
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.post("/b/links", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_links(req: ReadReq, session: str = "default"):
    limit = max(1, min(req.maxChars // 120, 120))
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            if s.page is None:
                raise HTTPException(status_code=409, detail="no page open")
            try:
                links = await s.page.get_links(limit=limit)
                s.actions += 1
                s.touch()
                return {"url": s.url, "count": len(links), "links": links}
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.post("/b/click", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_click(req: SelectorReq, session: str = "default"):
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            if s.page is None:
                raise HTTPException(status_code=409, detail="no page open")
            try:
                res = await s.page.click(req.selector, timeout=10.0)
                s.actions += 1
                s.touch()
                try:
                    s.url = await s.page.current_url()
                    s.title = await s.page.title_now()
                except Exception:
                    pass
                return {**res, "url": s.url, "title": s.title, "memory": memory_report()}
            except BrowserError as e:
                raise HTTPException(status_code=404, detail=str(e)[:250])
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.post("/b/fill", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_fill(req: FillReq, session: str = "default"):
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            if s.page is None:
                raise HTTPException(status_code=409, detail="no page open")
            try:
                res = await s.page.fill(req.selector, req.text)
                s.actions += 1
                s.touch()
                return res
            except BrowserError as e:
                raise HTTPException(status_code=404, detail=str(e)[:250])
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.post("/b/press", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_press(req: PressReq, session: str = "default"):
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            if s.page is None:
                raise HTTPException(status_code=409, detail="no page open")
            try:
                res = await s.page.press(req.key)
                s.actions += 1
                s.touch()
                try:
                    s.url = await s.page.current_url()
                except Exception:
                    pass
                return {**res, "url": s.url}
            except BrowserError as e:
                raise HTTPException(status_code=400, detail=str(e)[:250])
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.post("/b/scroll", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_scroll(req: ScrollReq, session: str = "default"):
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            if s.page is None:
                raise HTTPException(status_code=409, detail="no page open")
            try:
                res = await s.page.scroll(req.direction, req.amount)
                s.actions += 1
                s.touch()
                return res
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.post("/b/back", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_back(session: str = "default"):
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            if s.page is None:
                raise HTTPException(status_code=409, detail="no page open")
            try:
                res = await s.page.go_back()
                s.url = res.get("url", s.url)
                s.title = res.get("title", s.title)
                s.actions += 1
                s.touch()
                return {"url": s.url, "title": s.title}
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.post("/b/screenshot", dependencies=[Depends(require_token), Depends(require_rate_limit)])
async def b_shot(req: ShotReq, session: str = "default"):
    async with manager.gate:
        s = manager.get(session)
        async with s.lock:
            if s.page is None:
                raise HTTPException(status_code=409, detail="no page open")
            try:
                png_b64 = await s.page.screenshot(full_page=req.fullPage)
                raw = base64.b64decode(png_b64)
                s.actions += 1
                s.touch()
                capped = len(raw) > 900_000
                return {
                    "mime": "image/png",
                    "bytes": len(raw),
                    "truncated": capped,
                    "data_base64": png_b64 if not capped else png_b64[:1_200_000],
                }
            except Exception as e:
                await s.teardown()
                raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)[:250]}")


@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(f"""<!DOCTYPE html><html lang="he" dir="rtl">
<head><meta charset="utf-8"><title>browser-server</title>
<style>body{{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:28px;direction:rtl}}
code{{background:#1e293b;padding:2px 6px;border-radius:4px}}</style></head><body>
<h1>browser-server</h1>
<p>שירת דפדפן headless לסוכן AI. רצה בתוך 512MB.</p>
<pre>{memory_report()}</pre>
<p>נתיבים: <code>POST /b/open</code> <code>/b/read</code> <code>/b/links</code>
<code>/b/click</code> <code>/b/fill</code> <code>/b/press</code>
<code>/b/scroll</code> <code>/b/back</code> <code>/b/screenshot</code></p>
<p>כל הנתיבים דורשים כותרת <code>X-Browser-Token</code>.</p>
<p><code>GET /healthz</code> · <code>GET /b/state</code></p>
</body></html>""")
