"""
שלב 0 - בדיקת אפשרות: האם Chromium נכנס ב-512MB של Render Free?

השירות הזה אינו חלק מהמערכת. מטרתו להוכיח או להפיך את ההנחה
שאפשר להריץ דפדפן בתוכנית החינמית, לפני שמשקיעים ימים בכתיבת הסוכן.

הוא מפעיל Chromium ישירות דרך CDP (בלי Playwright, שאכל 108MB),
טוען דפים בכבדות עולה, ומדווח כמה זיכרון נאכל בפועל.

⚠️ תיקון חשוב: verdict מחושב לפי שיא הזיכרון *ואם הדפדפן שרד*.
בגרסה הקודמת המדד נלקח אחרי שהדפדפן כבר נפל, ולכן דיווח "נכנס בנוחות"
גם כשהתקלה הייתה OOM. הפעם זה לא יקרה שוב.
"""
from __future__ import annotations

import asyncio
import gc
import os
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from cdp import CDP, BrowserError, find_browser

app = FastAPI(title="chromium-fit-probe", version="2.0")

MEMORY_LIMIT_MB = 512
# Playwright אכל 108MB מתוך 512. ב-CDP הוא לא קיים, ולכן התקציב גדול יותר.
PYTHON_OVERHEAD_MB = 90

TEST_PAGES = [
    ("example", "https://example.com", "דף מינימלי - רצפה"),
    ("wikipedia-he", "https://he.wikipedia.org/wiki/ישראל", "תוכן אמיתי, JS, תמונות - המבחן"),
    ("duckduckgo", "https://duckduckgo.com/?q=test", "אתר חיפוש דינמי"),
]


def _read_rss_kb(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", "r") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
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


def _read_pss_kb(pid: int) -> int:
    """PSS - Proportional Set Size.

    ⚠️ זה המדד הנכון, ולא RSS. כל תהליך ב-Chromium חולק ספריות ו-mappings
    עם תהליבים אחרים. RSS סופר זיכרון משותף פעם לכל תהליך שנוגע בו,
    ולכן סכום RSS של 3 תהליכים יכול להפיל פי 2-3 מהצריכה האמיתית.
    מגבלת הזיכרון של הקונטיינר סופרת כל עמוד פעם אחת - בדיוק כמו PSS.
    """
    try:
        with open(f"/proc/{pid}/smaps_rollup", "r") as fh:
            for line in fh:
                if line.startswith("Pss:"):
                    return int(line.split()[1])
    except Exception:
        pass
    return 0


def memory_report() -> Dict[str, Any]:
    chromium = pss = rss = node = python = 0
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
            chromium += 1
            procs += 1
            pss += _read_pss_kb(pid)
            rss += _read_rss_kb(pid)
        elif "playwright" in low and "node" in low:
            node += _read_rss_kb(pid)
        elif "uvicorn" in low or "python" in low:
            python += _read_pss_kb(pid) or _read_rss_kb(pid)
    return {
        # PSS = המדידה המכריעה
        "total_pss_mb": round((pss + node + python) / 1024, 1),
        "chromium_pss_mb": round(pss / 1024, 1),
        "chromium_rss_mb": round(rss / 1024, 1),   # להשוואה
        "node_driver_pss_mb": round(node / 1024, 1),
        "python_pss_mb": round(python / 1024, 1),
        "chromium_processes": procs,
        "limit_mb": MEMORY_LIMIT_MB,
        "budget_for_chromium_mb": MEMORY_LIMIT_MB - PYTHON_OVERHEAD_MB,
    }


def _rss() -> float:
    return memory_report()["total_rss_mb"]


async def run_probe() -> Dict[str, Any]:
    result: Dict[str, Any] = {"mode": "direct-cdp", "fresh_page_per_navigation": True, "steps": []}
    peak_pss = 0.0
    peak_rss = 0.0
    cdp = CDP()

    def note(step: str, **kw: Any) -> None:
        nonlocal peak_pss, peak_rss
        mem = memory_report()
        peak_pss = max(peak_pss, mem["total_pss_mb"])
        peak_rss = max(peak_rss, mem["chromium_rss_mb"])
        entry = {"step": step, "memory": mem}
        entry.update(kw)
        result["steps"].append(entry)

    try:
        result["binary"] = find_browser()
    except BrowserError as e:
        result["error"] = str(e)
        result["verdict"] = {"fits": False, "headroom_mb": 0,
                             "message": "לא נמצאה התקנת Chromium", "crashed": True}
        return result

    try:
        t0 = time.time()
        page = await cdp.new_page()
        result["launch_ms"] = int((time.time() - t0) * 1000)
        note("chromium_launched")
        try:
            result["version"] = (await cdp.send("Browser.getVersion")).get("product", "")
        except Exception:
            result["version"] = "unknown"

        for name, url, note_txt in TEST_PAGES:
            step: Dict[str, Any] = {"name": name, "note": note_txt}
            # דף נקי לכל ניווט: בדיקה קודמת הראתה שהזיכרון גדל באופן
            # מונוטוני (429 -> 468 -> 592MB) כשמשתמשים באותו טאב.
            try:
                await page.close()
            except Exception:
                pass
            try:
                page = await cdp.new_page()
            except Exception as e2:
                step["ok"] = False
                step["error"] = f"new_page failed: {str(e2)[:150]}"
                note("load", **step)
                break

            try:
                t0 = time.time()
                res = await page.goto(url, timeout=15.0)
                step["load_ms"] = int((time.time() - t0) * 1000)
                step["url"] = res.get("url")
                step["title"] = (res.get("title") or "")[:120]
                page_info = await page.read_page(max_chars=4000)
                step["text_chars"] = len(page_info["text"])
                step["ok"] = True
            except Exception as e:
                step["ok"] = False
                step["error"] = f"{type(e).__name__}: {str(e)[:200]}"
            note("load", **step)

        try:
            await cdp.stop()
        except Exception:
            pass
        gc.collect()
        note("after_shutdown")
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:300]}"
        try:
            await cdp.stop()
        except Exception:
            pass

    # ---- פסק חסין, לפי PSS (המדד שמתאים למגבלת הקונטיינר) ----
    loaded = [s for s in result["steps"] if s.get("step") == "load"]
    successes = [s for s in loaded if s.get("ok")]
    crashed = not bool(successes) or bool(result.get("error"))

    headroom = MEMORY_LIMIT_MB - peak_pss
    if not successes:
        verdict = {"fits": False, "headroom_mb": round(headroom, 1),
                   "message": "הדפדפן לא העלה אף דף - נפל", "crashed": True}
    elif len(successes) < len(TEST_PAGES):
        failed = [s["name"] for s in loaded if not s.get("ok")]
        verdict = {"fits": False, "headroom_mb": round(headroom, 1),
                   "message": f"נכשל ב: {', '.join(failed)}", "crashed": True}
    elif headroom > 100:
        verdict = {"fits": True, "headroom_mb": round(headroom, 1),
                   "message": "עבר בהצלחה את כל הדפים, עם מרווח מספיק", "crashed": False}
    elif headroom > 30:
        verdict = {"fits": True, "headroom_mb": round(headroom, 1),
                   "message": "עבר את כל הדפים במצוקה - דפדפן אחד, סגירה מיידית", "crashed": False}
    else:
        verdict = {"fits": False, "headroom_mb": round(headroom, 1),
                   "message": "המרווח קטן מדי גם לפי PSS", "crashed": False}

    result["peak_pss_mb"] = round(peak_pss, 1)
    result["peak_chromium_rss_mb"] = round(peak_rss, 1)
    result["metric"] = "PSS (smaps_rollup) - accounts shared memory correctly"
    result["pages_loaded"] = f"{len(successes)}/{len(TEST_PAGES)}"
    result["verdict"] = verdict
    return result


@app.get("/healthz")
def healthz():
    return {"status": "ok", "memory": memory_report()}


@app.get("/browsers")
def browsers():
    """אבחון התקנת Chromium - מה באמת קיים בדיסק."""
    from cdp import browser_inventory
    try:
        return browser_inventory()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:300]}"}


# הבדיקה רצה 2-3 דקות. בקשה סינכרונית כזו היא שגויה: השרת יכול להיפגע
# באמצע, הלקוח ינתק, ואין דרך לשאול מה קרה. לכן הרצה ברקע + polling.
_probe_state: Dict[str, Any] = {"status": "idle", "started_at": None, "result": None, "error": None}
_probe_lock = asyncio.Lock()


@app.get("/probe", response_class=JSONResponse)
async def probe_status():
    return JSONResponse(content=dict(_probe_state))


@app.post("/probe", response_class=JSONResponse)
async def probe_start():
    async with _probe_lock:
        if _probe_state["status"] == "running":
            return JSONResponse(content={"status": "running", "note": "כבר רץ"})

        _probe_state.update({"status": "running", "started_at": time.time(),
                             "result": None, "error": None})

        async def _job() -> None:
            try:
                _probe_state["result"] = await run_probe()
                _probe_state["status"] = "done"
            except Exception as e:
                _probe_state["error"] = f"{type(e).__name__}: {str(e)[:300]}"
                _probe_state["status"] = "failed"
            finally:
                gc.collect()

        asyncio.create_task(_job())
        return JSONResponse(content={"status": "running", "note": "הבדיקה החלה"})


@app.get("/probe/result", response_class=JSONResponse)
async def probe_result():
    """תוצאה מלאה בלבד, או null אם עדיין רצה."""
    if _probe_state["status"] == "done":
        return JSONResponse(content=_probe_state["result"])
    return JSONResponse(content={
        "status": _probe_state["status"],
        "error": _probe_state["error"],
        "memory": memory_report(),
    })


@app.get("/", response_class=HTMLResponse)
def home():
    mem = memory_report()
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="he" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>בדיקת Chromium</title>
<style>body{{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:26px;direction:rtl}}
h1{{font-size:21px}}pre{{background:#1e293b;padding:12px;border-radius:8px;overflow:auto;font-size:13px}}
a{{color:#38bdf8}}</style></head><body>
<h1>בדיקת Chromium ב-Render Free (512MB)</h1>
<pre>{mem}</pre>
<p><a href="/probe">הרץ בדיקה מלאה</a> (3 דפים, כ-30 שניות)</p>
</body></html>""")
