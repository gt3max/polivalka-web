# CLAUDE.MD - Cloud Web контекст

## Это Cloud сайт проекта Polivalka (plantapp.pro)

**ОСНОВНАЯ ДОКУМЕНТАЦИЯ:** `/Users/maximshurygin/Polivalka/CLAUDE.md`

---

## ⚠️ ТРИ РЕПОЗИТОРИЯ - КРИТИЧЕСКИ ВАЖНО!

**Проект состоит из ТРЁХ git репозиториев:**

| Папка | GitHub | Назначение |
|-------|--------|------------|
| `/Users/maximshurygin/Polivalka` | gt3max/Polivalka | ESP32 firmware + Lambda + документация |
| `/Users/maximshurygin/polivalka-web` | gt3max/polivalka-web | Cloud сайт (plantapp.pro) |
| `/Users/maximshurygin/plantapp` | gt3max/plantapp | Мобильное приложение PlantApp (React Native + Expo) |

**ПРАВИЛО СИНХРОНИЗАЦИИ:** Все 3 клиента → один бэкенд.
- Изменил UI логику → проверяй AP (`components/website/`) и Cloud (этот репо)
- Изменил API endpoint → проверить ВСЕ клиенты (сайт + приложение + ESP32)
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

---

## Для полной документации

Читай `/Users/maximshurygin/Polivalka/CLAUDE.md` - там:
- Best practices всех областей
- Git workflow
- AWS/Lambda информация
- Диаграммы и архитектура
