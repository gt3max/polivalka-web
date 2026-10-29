#!/usr/bin/env python3
"""Сторож личных данных: в репозиторий не уходят почты людей, телефоны, токены, выгрузки, скриншоты.

🔴 Зачем (29.10.2026). GitHub у нас — чтобы восстановить код, если пропадёт ноутбук. Личные данные для работы
приложения не нужны, а правило «ни в один репо, включая приватный» (`~/.claude/rules_reasons.md`, «NDA и личные
данные», 04.09.2026) два месяца стояло без механизма: хуки ловили пароли и ключи, а почты владельца, дизайнера,
пользователей и посторонних людей уходили в код и в публичный сайт. Разбор — plantapp
`documentation/Fable/2026-10-29_pii_guard_design.md`.

Разумные пределы (минимизация данных): нельзя то, что указывает на конкретного человека через наш сервис.
Имена (авторы фото CC BY, учёные), организации, деловые адреса служб, примеры — можно.

Что останавливает:
  • почту с доменом не из `.pii-allow` (gmail, icloud, адреса-прослойки Apple, любой незнакомый);
  • телефон с «+» и кодом страны; токен входа (JWT);
  • НОВЫЙ файл-выгрузку (csv, jsonl, sqlite, db, xlsx, log, har, parquet) или картинку вне разрешённых папок;
  • НОВЫЙ не-кодовый файл с именем вида backup / export / dump / users / screenshot / _private / .bak.

Одна и та же копия лежит в `scripts/git-hooks/` всех четырёх репозиториев (тест сверяет). Разрешения — в
`.pii-allow` корня каждого репо: `domain <домен>`, `data <папка/>`, `img <папка/>` (`./` — файлы в корне),
после `#` — причина. Список «запрещённых адресов» не ведём: он сам был бы перечнем тайн.

Режимы:
  pii_guard.py                — что добавлено в коммит (pre-commit);
  pii_guard.py --range A B    — что добавляют коммиты между A и B (pre-push);
  pii_guard.py --tree         — всё дерево (чистка, CI).
"""
import os
import re
import subprocess
import sys

#: Домен — в нормальной форме, зона строчными буквами: обрывки base64 и двоичных данных («mR-.Qo») не почта.
EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[a-z]{2,})\b')
PHONE = re.compile(r'(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?!\w)')
JWT = re.compile(r'eyJ[\w-]{10,}\.eyJ[\w-]{10,}')
DATA_EXT = ('.csv', '.jsonl', '.sqlite', '.sqlite3', '.db', '.xlsx', '.xls', '.log', '.har', '.parquet')
IMG_EXT = ('.png', '.jpg', '.jpeg', '.webp', '.heic', '.gif')
CODE_EXT = ('.py', '.dart', '.js', '.ts', '.html', '.css', '.md', '.sh', '.yml', '.yaml', '.c', '.h',
            '.swift', '.kt', '.gradle', '.txt', '.json', '.toml', '.cfg', '.ini', '.sql', '.xml', '.plist')
BAD_NAME = re.compile(r'(backup|export|dump|users?[_-]|screenshot|_private|\.bak)', re.I)


def git(*a, check=True):
    return subprocess.run(['git', *a], capture_output=True, text=True, check=check).stdout


def load_allow(root):
    allow = {'domain': set(), 'data': [], 'img': []}
    try:
        lines = open(os.path.join(root, '.pii-allow'), encoding='utf-8').read().splitlines()
    except FileNotFoundError:
        lines = []
    for ln in lines:
        ln = ln.split('#', 1)[0].strip()
        if not ln:
            continue
        kind, _, val = ln.partition(' ')
        if kind in allow:
            (allow[kind].add if kind == 'domain' else allow[kind].append)(val.strip().lower())
    return allow


def domain_ok(dom, allow):
    dom = dom.lower()
    return any(dom == d or dom.endswith('.' + d) for d in allow['domain'])


def path_ok(path, prefixes):
    return any((p == './' and '/' not in path) or path.startswith(p) for p in prefixes)


def check_line(path, n, line, allow, out):
    for m in EMAIL.finditer(line):
        if re.match(r'[123]x\.', m.group(1)):          # image@2x.png
            continue
        if not domain_ok(m.group(1), allow):
            out.append(f'{path}:{n}: почта с доменом «{m.group(1)}» — личный адрес? '
                       f'Если это деловой адрес службы — `domain {m.group(1)}  # причина` в .pii-allow')
    if JWT.search(line):
        out.append(f'{path}:{n}: токен входа (JWT)')
    for m in PHONE.finditer(line):
        if len(re.sub(r'\D', '', m.group(0))) >= 10:
            out.append(f'{path}:{n}: телефон «{m.group(0).strip()}»')


def check_new_file(path, allow, out):
    low = path.lower()
    if low.endswith(DATA_EXT) and not path_ok(path, allow['data']):
        out.append(f'{path}: новый файл-выгрузка — данные людей живут вне репо '
                   f'(папка данных каталога? — `data {os.path.dirname(path)}/  # причина` в .pii-allow)')
    if low.endswith(IMG_EXT) and not path_ok(path, allow['img']):
        out.append(f'{path}: новая картинка вне папок ресурсов — скриншоты и фото людей в репо не кладём')
    if not low.endswith(CODE_EXT + IMG_EXT + DATA_EXT) or low.endswith(DATA_EXT):
        if BAD_NAME.search(path):
            out.append(f'{path}: имя похоже на выгрузку или копию (backup/export/dump/users/…)')


def scan_text(path, text, allow, out, only_lines=None):
    for n, line in enumerate(text.splitlines(), 1):
        if only_lines is None or n in only_lines:
            check_line(path, n, line, allow, out)


def added_lines(diff_text):
    """{путь: {номер строки: текст}} из `git diff -U0`."""
    res, path, n = {}, None, 0
    for ln in diff_text.splitlines():
        if ln.startswith('+++ '):
            path = ln[6:] if ln.startswith('+++ b/') else None
        elif ln.startswith('@@'):
            m = re.search(r'\+(\d+)', ln)
            n = int(m.group(1)) if m else 0
        elif path and ln.startswith('+') and not ln.startswith('+++'):
            res.setdefault(path, {})[n] = ln[1:]
            n += 1
    return res


def scan_diff(diff_args, names_args, allow):
    out = []
    for path in git(*names_args).splitlines():
        check_new_file(path, allow, out)
    for path, lines in added_lines(git(*diff_args)).items():
        if path.lower().endswith(IMG_EXT + ('.sqlite', '.db', '.xlsx', '.parquet')):
            continue
        for n, line in lines.items():
            check_line(path, n, line, allow, out)
    return out


def main(argv):
    root = git('rev-parse', '--show-toplevel').strip()
    os.chdir(root)
    allow = load_allow(root)
    if '--tree' in argv:
        out = []
        for path in git('ls-files').splitlines():
            if path.lower().endswith(IMG_EXT + ('.sqlite', '.db', '.xlsx', '.parquet')):
                continue
            try:
                raw = open(path, 'rb').read()
            except (IsADirectoryError, FileNotFoundError):
                continue
            if b'\0' in raw[:8192]:                          # двоичный файл
                continue
            scan_text(path, raw.decode('utf-8', errors='ignore'), allow, out)
    elif '--range' in argv:
        a, b = argv[argv.index('--range') + 1:argv.index('--range') + 3]
        out = scan_diff(['diff', '-U0', '--no-color', a, b],
                        ['diff', '--name-only', '--diff-filter=A', a, b], allow)
    else:
        out = scan_diff(['diff', '--cached', '-U0', '--no-color'],
                        ['diff', '--cached', '--name-only', '--diff-filter=A'], allow)
    if out:
        print('\n✗ ОСТАНОВЛЕНО — похоже на личные данные (scripts/git-hooks/pii_guard.py):\n', file=sys.stderr)
        for o in out[:60]:
            print('  ' + o, file=sys.stderr)
        if len(out) > 60:
            print(f'  … и ещё {len(out) - 60}', file=sys.stderr)
        print('\nЛичное — убрать из файла (роль вместо адреса, данные — вне репо). Законное деловое или пример —\n'
              'внести домен/папку в .pii-allow с причиной.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
