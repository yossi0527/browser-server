"""
שלב 0 - בדיקת אפשרות: האם Chromium נכנס ב-512MB של Render Free?

השירות הזה אינו חלק מהמערכת. מטרתו להוכיח או להפיך את ההנחה
שאפשר להריץ דפדפן בתוכנית החינמית, לפני שמשקיעים ימים בכתיבת הסוכן.

הוא מנסה Chromium עם דגלים אגרסיביים, טוען שלושה סוגי דפים,
ומדווח כמה זיכרון נאכל בפועל.
"""
from __future__ import annotations

import gc
import json
import os
import time
from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="chromium-fit-probe", version="1.0")

# Render Free: 0.1 CPU / 512MB. כולל את ה-Python עצמו.
MEMORY_LIMIT_MB = 512
OVERHEAD_ALLOWANCE_MB = 90  # Python + FastAPI + uvicorn + ה-playwright driver

LAUNCH_ARGS = [
    "--headless=new",
    "--no-sandbox",
    "--disable-dev-shm-usage",       # חשוב: /dev/shm זעיר בקונטיינרים
    "--disable-gpu",
    "--single-process",              # חוסך זיכרון, יציב יותר
    "--renderer-process-limit=1",
    "--disable-extensions",
    "--disable-software-rasterizer",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-translate",
    "--mute-audio",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-features=TranslateUI,BackForwardCache,AcceptCHFrame,MediaRouter,OptimizationHints",
    "--blink-settings=imagesEnabled=false",   # אתרים בלי תמונות = חיסכון רצוף
    "--js-flags=--max-old-space-size=128",
]

# דפים מדורגים לפי כבדות, כדי לדעת איפה נשבר.
TEST_PAGES = [
    ("example", "https://example.com", "דף מינימלי"),
    ("wikipedia", "https://he.wikipedia.org/wiki/ישראל", "תוכן עמוד טקסטואלי + תמונות"),
    ("wikipedia-light", "https://he.wikipedia.org/api/rest_v1/page/html/ישראל", "אותו ערך, בלי JS"),
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


def _proc_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return fh.read().replace(b"\0", b" ").decode("utf-8", "replace")
    except Exception:
        return ""


def memory_report() -> Dict[str, Any]:
    """סורק את כל תהליבי ה-chromium וה-node ומחזיר זיכרון."""
    chromium = 0
    node = 0
    others = 0
    count = 0
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        cmd = _proc_cmdline(pid)
        if not cmd:
            continue
        low = cmd.lower()
        if "headless_shell" in low or "chrome" in low or "chromium" in low:
            chromium += _read_rss_kb(pid)
            count += 1
        elif "playwright" in low and "node" in low:
            node += _read_rss_kb(pid)
        elif "uvicorn" in low or "python" in low:
            others += _read_rss_kb(pid)
    total_kb = chromium + node + others
    return {
        "chromium_rss_mb": round(chromium / 1024, 1),
        "playwright_driver_rss_mb": round(node / 1024, 1),
        "python_rss_mb": round(others / 1024, 1),
        "total_rss_mb": round(total_kb / 1024, 1),
        "chromium_processes": count,
        "limit_mb": MEMORY_LIMIT_MB,
        "budget_for_chromium_mb": MEMORY_LIMIT_MB - OVERHEAD_ALLOWANCE_MB,
    }


def verdict(rep: Dict[str, Any]) -> Dict[str, Any]:
    total = rep["total_rss_mb"]
    headroom = MEMORY_LIMIT_MB - total
    if total <= 0:
        ok = None
        msg = "לא נמדד זיכרון"
    elif headroom > 120:
        ok, msg = True, "נכנס בנוחות. אפשר לבנות את הסוכן עם Playwright."
    elif headroom > 40:
        ok, msg = True, "נכנס, אך במצוקה. צריך להריץ דפדפן אחד בלבד ולסגור מהר."
    elif headroom > 0:
        ok, msg = None, "גבולי מאוד. יכול לעבוד, אבל כל עוד סרקוד יפיל אותו."
    else:
        ok, msg = False, "חריג מהמגבלת - Chromium לא יתאים ל-Render Free."
    return {"fits": ok, "headroom_mb": round(headroom, 1), "message": msg}


async def run_probe() -> Dict[str, Any]:
    from playwright.async_api import async_playwright

    result: Dict[str, Any] = {"launch_args": LAUNCH_ARGS, "steps": []}
    t0 = time.time()
    pw = await async_playwright().start()
    result["playwright_start_ms"] = int((time.time() - t0) * 1000)
    result["steps"].append({"step": "playwright_started",
                            "memory": memory_report()})

    browser = None
    try:
        t0 = time.time()
        browser = await pw.chromium.launch(args=LAUNCH_ARGS, headless=True)
        result["launch_ms"] = int((time.time() - t0) * 1000)
        result["version"] = browser.version
        result["steps"].append({"step": "chromium_launched",
                                "memory": memory_report()})

        for name, url, note in TEST_PAGES:
            step: Dict[str, Any] = {"step": "load", "name": name, "note": note}
            page = None
            try:
                t0 = time.time()
                page = await browser.new_page(
                    viewport={"width": 1280, "height": 800},
                    java_script_enabled=True,
                )
                page.set_default_timeout(20000)
                resp = await page.goto(url, wait_until="domcontentloaded", timeout=20000)
                step["status"] = resp.status if resp else None
                step["load_ms"] = int((time.time() - t0) * 1000)
                step["title"] = (await page.title())[:120]
                body = await page.evaluate(
                    "() => document.body ? document.body.innerText : ''"
                )
                step["text_chars"] = len(body or "")
            except Exception as e:
                step["error"] = f"{type(e).__name__}: {str(e)[:200]}"
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass
            step["memory"] = memory_report()
            result["steps"].append(step)

        result["final"] = memory_report()
        result["verdict"] = verdict(result["final"])
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {str(e)[:400]}"
        result["final"] = memory_report()
        result["verdict"] = {
            "fits": False,
            "headroom_mb": MEMORY_LIMIT_MB - result["final"]["total_rss_mb"],
            "message": "Chromium לא עלה כלל - יש לבדוק את התקנת הדפדפן.",
        }
    finally:
        if browser:
            try:
                await browser.close()
            except Exception:
                pass
        gc.collect()
        try:
            await pw.stop()
        except Exception:
            pass

    result["after_shutdown"] = memory_report()
    return result


@app.get("/healthz")
def healthz():
    return {"status": "ok", "memory": memory_report()}


@app.get("/probe", response_class=JSONResponse)
async def probe():
    return JSONResponse(content=await run_probe())


@app.get("/", response_class=HTMLResponse)
def home():
    mem = memory_report()
    v = verdict(mem)
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="he" dir="rtl"><head><meta charset="utf-8">
<title>בדיקת Chromium</title>
<style>body{{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:30px;
direction:rtl}}h1{{font-size:22px}}.k{{background:#1e293b;padding:10px 14px;
border-radius:8px;margin:6px 0;font-family:monospace}}a{{color:#38bdf8}}
.ok{{color:#4ade80}}.bad{{color:#f87171}}</style></head><body>
<h1>בדיקת אפשרות - Chromium ב-Render Free</h1>
<p>מגבלה: <b>{MEMORY_LIMIT_MB}MB</b> · יעד לדפדפן: <b>{mem['budget_for_chromium_mb']}MB</b></p>
<div class="k">זיכרון כולל: <b>{mem['total_rss_mb']}MB</b></div>
<div class="k">Chromium: {mem['chromium_rss_mb']}MB ({mem['chromium_processes']} תהליכים)</div>
<div class="k">Playwright driver: {mem['playwright_driver_rss_mb']}MB</div>
<div class="k">Python: {mem['python_rss_mb']}MB</div>
<p class="{'ok' if v['fits'] else 'bad'}"><b>{v['message']}</b> (מרווח {v['headroom_mb']}MB)</p>
<p><a href="/probe">הרץ את הבדיקה המלאה</a> (כ-30 שניות, מפעיל דפדפן אמיתי)</p>
</body></html>""")


class KeepAlive(BaseModel):
    seconds: int = 300


@app.post("/keepalive")
async def keepalive(req: KeepAlive):
    """מעכב את ההתנחשות של Render Free בזמן שמבצעים בדיקות."""
    seconds = max(1, min(req.seconds, 900))
    started = time.time()
    while time.time() - started < seconds:
        time.sleep(5)
    return {"kept_alive_sec": int(time.time() - started), "memory": memory_report()}
