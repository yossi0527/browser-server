"""
לקוח Chrome DevTools Protocol ישיר - בלי Playwright.

למה לא Playwright: מנהל ההתהליכים שלו (Node) אכל 108MB מתוך 512MB של
Render Free - 29% מהתקציב. ב-CDP ישיר העלות היחידה היא Python.

Chromium עצמו מגיע דרך playwright install (הוא מכיל את הספריות של המערכת),
אבל ברגע שהוא עלה - אנחו מדברים איתו ישירות דרך WebSocket.
"""
from __future__ import annotations

import asyncio
import base64
import glob
import json
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Playwright מגדיר את הנתיב; אם לא - ברירת מחדל מתאימה
BROWSERS_PATH = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "/ms-playwright")

# דגלים חסכוניים. --single-process מקטין משמעותית את הזיכרון,
# ו-imagesEnabled=false חוסך טעינת תמונות שאנחנו לא צריכים לקרוא.
LAUNCH_ARGS = [
    "--remote-debugging-port=0",
    # לא מוסיפים --headless: ה-binary שאנחנו מפעילים הוא
    # chromium-headless-shell, שכבר headless לפי הגדרה. מעבר --headless
    # איתו גורם לתהליך לצאת מיד עם שגיאה.
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--mute-audio",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-translate",
    "--disable-extensions",
    "--disable-software-rasterizer",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-ipc-flooding-protection",
    "--disable-features=TranslateUI,BackForwardCache,AcceptCHFrame,MediaRouter,OptimizationHints,CalculateNativeWinOcclusion",
    "--blink-settings=imagesEnabled=false",
    "--js-flags=--max-old-space-size=128",
    "--window-size=1280,900",
    "--lang=he-IL",
]


class BrowserError(RuntimeError):
    pass


def find_browser() -> str:
    """מאתר את ההתקנה של Chromium. מעדיף headless_shell - קל יותר."""
    candidates: List[str] = []
    for pat in (
        "chromium_headless_shell-*/chrome-linux/headless_shell",
        "chromium_headless_shell-*/chrome-linux64/headless_shell",
        "chromium-*/chrome-linux/chrome",
        "chromium-*/chrome-linux64/chrome",
    ):
        candidates += sorted(glob.glob(os.path.join(BROWSERS_PATH, pat)))

    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    # נפילה חזרה ל-PATH המערכת
    for name in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        found = shutil.which(name)
        if found:
            return found
    raise BrowserError(
        f"No Chromium binary found under {BROWSERS_PATH}. "
        f"Globbed: {candidates}"
    )


# ---------------------------------------------------------------- SSRF guard
_BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal",
    "instance-data", "metadata",
}
_BLOCKED_PREFIXES = (
    "10.", "192.168.", "169.254.", "127.", "0.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.",
    "100.64.", "[::1]", "[fc", "[fd", "[fe80",
)


def check_url(url: str) -> str:
    """מאמת URL לפני ניווט - חוסם SSRF כדי שהשירות לא יהפוך לפרוקסי פתוח."""
    url = (url or "").strip()
    if not url:
        raise BrowserError("missing url")
    if not url.startswith(("http://", "https://")):
        raise BrowserError("only http/https allowed")

    host = (urlparse(url).hostname or "").lower()
    if not host:
        raise BrowserError("url has no host")
    if host in _BLOCKED_HOSTS or host.startswith(_BLOCKED_PREFIXES):
        raise BrowserError(f"blocked host: {host}")
    return url


class Page:
    """דף אחד בתוך דפדפן."""

    def __init__(self, cdp: "CDP", session_id: str, target_id: str):
        self._cdp = cdp
        self.session_id = session_id
        self.target_id = target_id
        self.url = "about:blank"
        self.title = ""

    async def _send(self, method: str, params: Optional[dict] = None) -> dict:
        return await self._cdp.send(method, params, session_id=self.session_id)

    # ------------------------------------------------------------ navigation
    async def goto(self, url: str, timeout: float = 25.0) -> dict:
        url = check_url(url)
        loaded = asyncio.Event()
        self._cdp._on_load = lambda sid: loaded.set() if sid == self.session_id else None

        res = await self._send("Page.navigate", {"url": url})
        if res.get("errorText"):
            raise BrowserError(f"navigate failed: {res['errorText']}")
        try:
            await asyncio.wait_for(loaded.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            # לא הקשיא - דפים רבים מעבירים הלאה; נמשיך ונבדוק את מה שיש
            pass
        self.url = url
        self.title = await self.title_now()
        return {"url": self.url, "title": self.title}

    async def go_back(self, timeout: float = 20.0) -> dict:
        loaded = asyncio.Event()
        self._cdp._on_load = lambda sid: loaded.set() if sid == self.session_id else None
        await self._send("Page.navigateToHistoryEntry", {"entryId": await self._history_id(0)})
        try:
            await asyncio.wait_for(loaded.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        self.url = await self.current_url()
        return {"url": self.url, "title": await self.title_now()}

    async def _history_id(self, offset: int) -> int:
        res = await self._send("Page.getNavigationHistory")
        entries = res.get("entries", [])
        idx = res.get("currentIndex", 0) + offset
        if 0 <= idx < len(entries):
            return entries[idx]["id"]
        raise BrowserError("no such history entry")

    async def current_url(self) -> str:
        res = await self._send("Runtime.evaluate", {"expression": "location.href", "returnByValue": True})
        return (res.get("result") or {}).get("value") or self.url

    async def title_now(self) -> str:
        res = await self._send("Runtime.evaluate", {"expression": "document.title", "returnByValue": True})
        return (res.get("result") or {}).get("value") or ""

    # ------------------------------------------------------------ evaluation
    async def evaluate(self, expression: str, timeout: float = 15.0) -> Any:
        res = await asyncio.wait_for(
            self._send("Runtime.evaluate", {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": True,
                "userGesture": True,
            }),
            timeout=timeout,
        )
        if "exceptionDetails" in res:
            details = res["exceptionDetails"]
            msg = (details.get("exception") or {}).get("description") or details.get("text")
            raise BrowserError(f"JS error: {str(msg)[:250]}")
        return (res.get("result") or {}).get("value")

    async def read_page(self, max_chars: int = 8000) -> dict:
        data = await self.evaluate(
            """(() => {
              const vis = el => {
                const s = getComputedStyle(el);
                return s.display !== 'none' && s.visibility !== 'hidden' && el.offsetParent !== null;
              };
              const main = document.querySelector('main, article, [role=main]') || document.body;
              const parts = [];
              const walk = (el, depth) => {
                if (depth > 25) return;
                for (const c of el.childNodes) {
                  if (c.nodeType === 3) {
                    const t = c.textContent.replace(/\\s+/g, ' ').trim();
                    if (t) parts.push(t);
                  } else if (c.nodeType === 1 && c.tagName !== 'SCRIPT' && c.tagName !== 'STYLE'
                             && c.tagName !== 'NOSCRIPT' && vis(c)) {
                    walk(c, depth + 1);
                  }
                }
              };
              walk(main, 0);
              return {
                title: document.title,
                url: location.href,
                text: parts.join('\\n').replace(/\\n{3,}/g, '\\n\\n')
              };
            })()"""
        )
        data = data or {}
        return {
            "url": data.get("url", self.url),
            "title": data.get("title", ""),
            "text": (data.get("text") or "")[:max_chars],
            "truncated": len(data.get("text") or "") > max_chars,
        }

    async def get_links(self, limit: int = 60, base: str = "") -> List[dict]:
        return await self.evaluate(
            """(() => {
              const out = [];
              const seen = new Set();
              for (const a of document.querySelectorAll('a[href]')) {
                if (out.length >= 120) break;
                let href = a.href;
                if (href.startsWith('javascript:') || href.startsWith('#')) continue;
                const text = (a.innerText || a.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 120);
                const key = href + '|' + text;
                if (seen.has(key)) continue;
                seen.add(key);
                out.push({ href: href, text: text });
              }
              return out;
            })()"""
        ) or []

    async def find_element(self, selector: str) -> Optional[dict]:
        """מחזיר מיקום ומידע על אלמנט, או None."""
        return await self.evaluate(
            """((sel) => {
              let el = null;
              try { el = document.querySelector(sel); } catch (e) { return { error: 'bad selector' }; }
              if (!el) return null;
              el.scrollIntoView({ block: 'center', inline: 'center' });
              const r = el.getBoundingClientRect();
              const cs = getComputedStyle(el);
              const text = (el.innerText || el.value || el.placeholder || el.getAttribute('aria-label') || el.getAttribute('name') || '').toString().replace(/\\s+/g, ' ').trim().slice(0, 120);
              return {
                found: true,
                tag: el.tagName.toLowerCase(),
                type: el.getAttribute('type') || '',
                text: text,
                visible: r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none',
                x: r.x + r.width / 2,
                y: r.y + r.height / 2
              };
            })(""" + json.dumps(selector) + ")"
        )

    async def wait_for(self, selector: str, timeout: float = 10.0, visible: bool = True) -> Optional[dict]:
        deadline = asyncio.get_event_loop().time() + timeout
        last = None
        while asyncio.get_event_loop().time() < deadline:
            last = await self.find_element(selector)
            if last and (not last.get("visible") is False or not visible):
                if last.get("visible") or not visible:
                    return last
            await asyncio.sleep(0.25)
        return last

    async def click(self, selector: str, timeout: float = 10.0) -> dict:
        info = await self.wait_for(selector, timeout=timeout)
        if not info or not info.get("found"):
            raise BrowserError(f"element not found: {selector}")
        if not info.get("visible"):
            raise BrowserError(f"element not visible: {selector}")
        for kind in ("mousePressed", "mouseReleased"):
            await self._send("Input.dispatchMouseEvent", {
                "type": kind, "x": info["x"], "y": info["y"],
                "button": "left", "clickCount": 1,
            })
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.3)
        return {"clicked": selector, "tag": info.get("tag"), "text": info.get("text", "")[:80]}

    async def fill(self, selector: str, text: str, clear: bool = True) -> dict:
        info = await self.wait_for(selector, timeout=10.0)
        if not info or not info.get("found"):
            raise BrowserError(f"field not found: {selector}")
        # ממקד ומנקה דרך JS, ואז מכניס טקסט דרך Input - עובד עם ריאקט ועם אנגולר
        await self.evaluate(
            """((sel, clear) => {
              const el = document.querySelector(sel);
              if (!el) return false;
              el.focus();
              if (clear) {
                if ('value' in el) {
                  const setter = Object.getOwnPropertyDescriptor(
                    el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype
                                               : HTMLInputElement.prototype, 'value');
                  if (setter) setter.set.call(el, ''); else el.value = '';
                }
                el.textContent = '';
              }
              el.focus();
              return true;
            })(""" + json.dumps(selector) + ", " + ("true" if clear else "false") + ")"
        )
        if text:
            await self._send("Input.insertText", {"text": text})
        await asyncio.sleep(0.1)
        actual = await self.evaluate(
            """((sel) => { const el = document.querySelector(sel); return el ? (el.value !== undefined ? el.value : el.textContent) : null; })(""" + json.dumps(selector) + ")"
        )
        return {"filled": selector, "value": (actual if isinstance(actual, str) else "")[:200]}

    async def press(self, key: str) -> dict:
        keymap = {
            "enter": {"windowsVirtualKeyCode": 13, "code": "Enter", "key": "Enter", "text": "\r"},
            "tab": {"windowsVirtualKeyCode": 9, "code": "Tab", "key": "Tab", "text": "\t"},
            "escape": {"windowsVirtualKeyCode": 27, "code": "Escape", "key": "Escape"},
            "backspace": {"windowsVirtualKeyCode": 8, "code": "Backspace", "key": "Backspace"},
            "arrowdown": {"windowsVirtualKeyCode": 40, "code": "ArrowDown", "key": "ArrowDown"},
            "arrowup": {"windowsVirtualKeyCode": 38, "code": "ArrowUp", "key": "ArrowUp"},
            "space": {"windowsVirtualKeyCode": 32, "code": "Space", "key": " ", "text": " "},
        }
        k = keymap.get((key or "enter").lower())
        if not k:
            raise BrowserError(f"unsupported key: {key}")
        common = {"key": k["key"], "code": k["code"],
                  "windowsVirtualKeyCode": k["windowsVirtualKeyCode"], "nativeVirtualKeyCode": k["windowsVirtualKeyCode"]}
        await self._send("Input.dispatchKeyEvent", {"type": "keyDown", **common, **({"text": k["text"]} if "text" in k else {})})
        await self._send("Input.dispatchKeyEvent", {"type": "keyUp", **common})
        await asyncio.sleep(0.2)
        return {"pressed": key}

    async def scroll(self, direction: str = "down", amount: Optional[int] = None) -> dict:
        dy = {"down": 600, "up": -600, "top": -100000, "bottom": 100000}.get(
            (direction or "down").lower(), 600)
        if amount:
            dy = int(amount)
        await self.evaluate(f"window.scrollBy(0, {dy})")
        await asyncio.sleep(0.2)
        pos = await self.evaluate("({y: window.scrollY, h: document.body.scrollHeight, v: window.innerHeight})")
        return {"scrolled": direction, "position": pos}

    async def screenshot(self, full_page: bool = False) -> str:
        params: Dict[str, Any] = {"format": "png"}
        if full_page:
            metrics = await self._send("Page.getLayoutMetrics")
            size = metrics.get("cssContentSize") or metrics.get("contentSize") or {}
            if size.get("width") and size.get("height"):
                params["clip"] = {
                    "x": 0, "y": 0, "width": size["width"],
                    "height": min(size["height"], 6000), "scale": 1,
                }
                params["captureBeyondViewport"] = True
        res = await self._send("Page.captureScreenshot", params, )
        return res.get("data", "")

    async def close(self) -> None:
        try:
            await self._cdp.send("Target.closeTarget", {"targetId": self.target_id})
        except Exception:
            pass


class CDP:
    """מנהל דפדפן אחד וחיבור CDP אחד."""

    _instance_lock = asyncio.Lock()

    def __init__(self) -> None:
        self.proc = None
        self._ws = None
        self._id = 0
        self._pending: Dict[int, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None
        self._on_load = None
        self.browser_ws_url = ""
        self._profile_dir: Optional[str] = None

    # ---------------------------------------------------------------- launch
    async def start(self) -> None:
        if self.proc is not None:
            return
        binary = find_browser()
        self._profile_dir = tempfile.mkdtemp(prefix="cdp-profile-")
        cmd = [binary, *LAUNCH_ARGS, f"--user-data-dir={self._profile_dir}", "about:blank"]
        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self.browser_ws_url = await self._read_ws_url()
        if not self.browser_ws_url:
            await self.stop()
            raise BrowserError("could not read DevTools websocket url from Chromium")

    async def _read_ws_url(self, timeout: float = 20.0) -> str:
        """Chromium מדפיס את כתובת ה-WebSocket על stderr."""
        async def _read() -> str:
            assert self.proc and self.proc.stderr
            while True:
                line = await self.proc.stderr.readline()
                if not line:
                    return ""
                text = line.decode("utf-8", "replace")
                m = re.search(r"(ws://\S+)", text)
                if m:
                    return m.group(1)
        try:
            return await asyncio.wait_for(_read(), timeout=timeout)
        except asyncio.TimeoutError:
            return ""

    # ------------------------------------------------------------------- CDP
    async def _connect(self) -> None:
        import websockets
        self._ws = await websockets.connect(
            self.browser_ws_url, max_size=64 * 1024 * 1024, ping_interval=None,
        )
        self._reader_task = asyncio.create_task(self._reader())

    async def _reader(self) -> None:
        try:
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(BrowserError(str(msg["error"])[:300]))
                        else:
                            fut.set_result(msg.get("result", {}))
                else:
                    method = msg.get("method")
                    params = msg.get("params", {})
                    if method == "Page.loadEventFired":
                        cb = self._on_load
                        self._on_load = None
                        if cb:
                            try:
                                cb(params.get("frameId"))
                            except Exception:
                                pass
        except Exception:
            pass

    async def send(self, method: str, params: Optional[dict] = None, session_id: Optional[str] = None) -> dict:
        if self._ws is None:
            raise BrowserError("not connected")
        self._id += 1
        mid = self._id
        payload: Dict[str, Any] = {"id": mid, "method": method, "params": params or {}}
        if session_id:
            payload["sessionId"] = session_id
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[mid] = fut
        await self._ws.send(json.dumps(payload))
        try:
            return await asyncio.wait_for(fut, timeout=40)
        except asyncio.TimeoutError:
            self._pending.pop(mid, None)
            raise BrowserError(f"timeout waiting for {method}")

    # ------------------------------------------------------------------ page
    async def new_page(self) -> Page:
        if self.proc is None:
            await self.start()
        if self._ws is None:
            await self._connect()
        res = await self.send("Target.createTarget", {"url": "about:blank"})
        target_id = res.get("targetId")
        if not target_id:
            raise BrowserError("Target.createTarget returned no id")
        res = await self.send("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        session_id = res.get("sessionId")
        if not session_id:
            raise BrowserError("Target.attachToTarget returned no sessionId")
        page = Page(self, session_id, target_id)
        for domain in ("Page.enable", "Runtime.enable", "Network.enable", "DOM.enable"):
            try:
                await page._send(domain, {})
            except Exception:
                pass
        return page

    async def stop(self) -> None:
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
        if self._reader_task:
            self._reader_task.cancel()
            self._reader_task = None
        if self.proc is not None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
        if self._profile_dir:
            shutil.rmtree(self._profile_dir, ignore_errors=True)
            self._profile_dir = None
