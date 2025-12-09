# CLAUDE.MD - Cloud Web контекст

## Это Cloud сайт проекта Polivalka (plantapp.pro)

**ОСНОВНАЯ ДОКУМЕНТАЦИЯ:** `/Users/maximshurygin/Polivalka/CLAUDE.md`

---

## ⚠️ ДВА РЕПОЗИТОРИЯ - КРИТИЧЕСКИ ВАЖНО!

**Проект состоит из ДВУХ git репозиториев:**

| Папка | GitHub | Назначение |
|-------|--------|------------|
| `/Users/maximshurygin/Polivalka` | gt3max/Polivalka | ESP32 firmware + документация |
| `/Users/maximshurygin/polivalka-web` | gt3max/polivalka-web | Cloud сайт (plantapp.pro) |

**ПРАВИЛО: Когда меняешь UI логику - проверяй ОБА места!**

Файлы которые должны быть синхронизированы:
- `home.html` - AP версия в `Polivalka/components/website/`, Cloud версия тут
- `sensor.html`, `timer.html`, `settings.html` и др. - аналогично

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
