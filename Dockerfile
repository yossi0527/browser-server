# ─────────────────────────────────────────────────────────────────────────────
# שלב 0 — בדיקת אפשרות: האם Chromium נכנס ב-Render Free (0.1 CPU / 512MB)?
#
# למה Docker? ב-Render Native נכשלת התקנת Chromium בשתי דרכים:
#   1) playwright install --with-deps  -> "su: Authentication failure" (אין root)
#   2) apt-get install                  -> "Read-only file system"
# ב-Docker הבנייה רצה כ-root עם מערכת קבצים כתיבה, ולכן apt עובד.
#
# למה לא להשתמש בתמונת mcr.microsoft.com/playwright/python ?
#   היא שוקלת כ-2.5GB. בתוכנית החינמית יש מגבלת דיסק, וזה סיכון מיותר.
#   python:3.11-slim היא כ-150MB, ו-Chromium עצמו כ-170MB.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# ספריות מערכת ש-Chromium זקוק להן. כאן (בניגוד ל-Render Native) זה עובד,
# כי הבנייה רצה כ-root על מערכת קבצים כתיבה.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libnss3 \
        libnspr4 \
        libdbus-1-3 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libpango-1.0-0 \
        libcairo2 \
        libasound2 \
        libatspi2.0-0 \
        libxshmfence1 \
        libxext6 \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# בלי --with-deps: כבר התקנו ידנית למעלה, והשלב הזה היה שהפיל את הבנייה.
RUN playwright install chromium

COPY . .

EXPOSE 8080

# Render מגדיר את PORT; כברירת מחדל 8080.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
