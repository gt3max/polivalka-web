# CLAUDE.MD - Cloud Web контекст

## Это Cloud сайт проекта Polivalka (plantapp.pro)

**ОСНОВНАЯ ДОКУМЕНТАЦИЯ:** `/Users/maximshurygin/Polivalka/CLAUDE.md`

---

## ⚠️ ЧЕТЫРЕ РЕПОЗИТОРИЯ - КРИТИЧЕСКИ ВАЖНО!

**Проект состоит из ЧЕТЫРЁХ git репозиториев (3 клиента + общий бэкенд):**

| Папка | GitHub | Назначение |
|-------|--------|------------|
| `/Users/maximshurygin/Polivalka` | gt3max/Polivalka | ESP32 firmware + документация |
| `/Users/maximshurygin/polivalka-web` | gt3max/polivalka-web | Cloud сайт (plantapp.pro) — ЭТОТ репо |
| `/Users/maximshurygin/plantapp` | gt3max/plantapp | Мобильное приложение PlantApp (React Native + Expo) |
| `/Users/maximshurygin/plantapp-cloud` | gt3max/plantapp-cloud | **Общий бэкенд** (AWS Lambda) для всех 3 клиентов |

**Серверного кода в этом репо больше НЕТ** — он весь в `plantapp-cloud` (вынесен 2026-06-13, `lambda/` здесь удалён). Деплой бэкенда: `cd /Users/maximshurygin/plantapp-cloud && python3 deploy_lambdas.py`.

**ПРАВИЛО СИНХРОНИЗАЦИИ:** Все 3 клиента → один общий бэкенд `plantapp-cloud`.
- Изменил UI логику → проверяй AP (`components/website/`) и Cloud (этот репо)
- Изменил API endpoint (в `plantapp-cloud`) → проверить ВСЕ клиенты (сайт + приложение + ESP32)
- Добавил фичу → нужен ли аналог в других клиентах?
- Несинхронизированные клиенты = баг

---

## Деплой Cloud сайта

```bash
cd /Users/maximshurygin/polivalka-web
git add . && git commit -m "описание"
git push origin main  # GitHub Pages автоматически обновит plantapp.pro
```

**ВАЖНО:** push в `main`, не в `develop`! GitHub Pages берёт файлы из main.

### Pre-commit hook (mandatory after `git clone`)

```bash
cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Hook сканирует staged-content на API keys, passwords, private keys,
`.env` файлы. После 5 leak-инцидентов — обязательная механическая
защита. **Не использовать `git commit --no-verify` без явной причины.**

---

## Для полной документации

Читай `/Users/maximshurygin/Polivalka/CLAUDE.md` - там:
- Best practices всех областей
- Git workflow
- AWS/Lambda информация
- Диаграммы и архитектура
