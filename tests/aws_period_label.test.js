/**
 * Подпись периода в карточке расходов AWS.
 *
 * 🔴 Зачем. До 24.09.2026 (W39) карточка раскладывала по службам ПОСЛЕДНИЙ ПОЛНЫЙ
 * месяц, а подписывала это сама, по последней строке истории. Владелец смотрел на
 * сентябрьский счёт $1.31 и на разложенный август — и августовские числа читались
 * как сентябрьские. Подпись обязана приходить с сервера и обязана быть КОРОТКОЙ:
 * длинные подписи уже ломали ширину карточек днём раньше.
 *
 * Функции живут прямо в `admin.html`, поэтому тест достаёт их из файла и исполняет.
 * Браузер не нужен.
 *
 * Запуск: node tests/aws_period_label.test.js
 */
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');

// Достаём ровно то, что проверяем, — вместе с таблицей месяцев.
const куски = ['const _AWS_MON', 'function awsPeriodLabel', 'function awsPeriodIsCurrent']
  .map(нач => {
    const i = html.indexOf(нач);
    if (i < 0) throw new Error('в admin.html не найдено: ' + нач);
    // до конца функции/строки: ищем строку, начинающуюся с `}` или `;` на нулевом отступе
    const хвост = html.slice(i);
    const м = /\n\}\n/.exec(хвост);
    return нач.startsWith('const') ? хвост.slice(0, хвост.indexOf('\n') + 1)
                                   : хвост.slice(0, м.index + 3);
  }).join('\n');

const песочница = {};
new Function('sandbox', куски + '\nsandbox.awsPeriodLabel = awsPeriodLabel;'
  + '\nsandbox.awsPeriodIsCurrent = awsPeriodIsCurrent;')(песочница);
const { awsPeriodLabel, awsPeriodIsCurrent } = песочница;

let прошло = 0, упало = 0;
function проверить(имя, условие, пояснение) {
  if (условие) { прошло++; console.log('  ✅ ' + имя); }
  else { упало++; console.log('  ❌ ' + имя + (пояснение ? ' — ' + пояснение : '')); }
}

console.log('\nПодпись периода:');

проверить('месяц к сегодняшнему дню',
  awsPeriodLabel('2026-09-01..2026-09-24') === 'Sep 1–24',
  'получено: ' + awsPeriodLabel('2026-09-01..2026-09-24'));

проверить('первое число месяца — один день',
  awsPeriodLabel('2026-10-01..2026-10-01') === 'Oct 1',
  'получено: ' + awsPeriodLabel('2026-10-01..2026-10-01'));

проверить('период через границу месяца',
  awsPeriodLabel('2026-08-28..2026-09-03') === 'Aug 28 – Sep 3',
  'получено: ' + awsPeriodLabel('2026-08-28..2026-09-03'));

проверить('🔴 подпись КОРОТКАЯ — не шире 16 знаков',
  awsPeriodLabel('2026-09-01..2026-09-24').length <= 16,
  'длинная подпись ломает ширину карточки');

проверить('🔴 мусор не подписываем вовсе',
  awsPeriodLabel('') === '' && awsPeriodLabel(null) === ''
  && awsPeriodLabel('2026-09') === '' && awsPeriodLabel(undefined) === '',
  'соврать о периоде хуже, чем промолчать');

console.log('\nТекущий ли период:');

const сейчас = new Date();
const этот = String(сейчас.getFullYear()) + '-'
  + String(сейчас.getMonth() + 1).padStart(2, '0');
проверить('текущий месяц опознан',
  awsPeriodIsCurrent(этот + '-01..' + этот + '-15') === true);
проверить('чужой месяц не опознан',
  awsPeriodIsCurrent('2001-03-01..2001-03-31') === false);
проверить('мусор не опознан',
  awsPeriodIsCurrent('') === false && awsPeriodIsCurrent(null) === false);

console.log('\nКарточка берёт период с сервера, а не выдумывает:');
проверить('🔴 подпись строится из by_service_period',
  /awsPeriodLabel\(d && d\.by_service_period\)/.test(html),
  'подпись снова считается на экране — именно так и появилась ошибка');
проверить('🔴 прежний способ убран',
  !/last full month/.test(html),
  'в карточке осталась подпись «last full month»');

console.log('\n' + (упало ? `❌ ${упало} не прошло, ${прошло} прошло`
                          : `✅ всё прошло (${прошло})`));
process.exit(упало ? 1 : 0);
