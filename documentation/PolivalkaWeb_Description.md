# PolivalkaWeb — Описание проекта (сайт / облачная панель plantapp.pro)

Это **основной документ (хаб) репозитория `polivalka-web`**. Общие принципы работы + модель видимости
репо — в глобальном `~/.claude/CLAUDE.md`. Соседние репо-хабы: приложение — `plantapp` (`PlantApp_Description`);
общий бэкенд (AWS) — `plantapp-cloud` (`Backend_Description`); устройства/прошивка — `Polivalka` (`Device_Description`).

## Что это
Статический сайт **plantapp.pro** — публичная облачная панель: лендинг + управление устройствами Polivalka
(fleet) + смежные с приложением страницы. Общается с **общим бэкендом** (`plantapp-cloud`: API Gateway → Lambda);
связка с устройствами/приложением — через него (база пользователей).

🔴 **Репо PUBLIC по необходимости** (хостинг GitHub Pages) → в нём НИКОГДА не должно быть секретов/PII.
Деплой: push в `main` → GitHub Pages → plantapp.pro. Публичный API-endpoint зашит в JS (не секрет).

## Карта (что где)
**Страницы (HTML):**
- Витрина/вход: `index.html`, `home.html`, `login.html`, `settings.html`, `404.html`, `privacy.html`, `terms.html`
- Устройства/флот: `fleet.html`, `admin.html`, `online.html`, `ota.html`
- Управление устройством: `timer.html`, `sensor.html`, `calibration.html`, `device-controller.js`
- Смежное с аппом: `identify.html`, `trends.html`, `test.html`
**Логика (JS):** `api-adapter.js` (адаптер к бэкенду, cloud-vs-local режим), `common.js`, `device-controller.js`
**Данные:** `data/weekly/*.json` (недельные агрегаты устройств — пишет `polivalka-weekly-aggregator` Lambda)
**Ассеты:** `*.svg` (favicon, monstera-паттерны)
**Доки:** `documentation/` — `README.md`, `PRODUCT_EVALUATION_*.md`, `SENSOR_MODE_AUDIT.md`, `PLANT_PROFILE_*.md`.
  ⚠️ `documentation/Screenshot*.jpg` — потенциальный PII в публичном репо, разобрать отдельной security-задачей.

## Деплой / связь
- `main` → GitHub Pages → **plantapp.pro** (публичный).
- Бэкенд: общий `plantapp-cloud` (API Gateway endpoint зашит в `api-adapter.js`), CORS whitelist на стороне Lambda.
