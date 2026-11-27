/**
 * Панель Jobs: одна строка — три колонки job | what it does | last; порядок — беда, деньги, данные, люди, разработка;
 * «только наблюдение» и «выключено» — серым; старый ответ сервера (без подписей) рисуется по-старому; ошибка
 * отрисовки не роняет админку (27.11.2026, W48).
 *
 * Браузер не нужен: функции берутся из admin.html, документ подменён.
 * Запуск: node tests/admin_jobs_panel.test.js
 */
const fs = require('fs');
const path = require('path');

let прошло = 0, упало = 0;
function проверить(имя, условие, пояснение) {
  if (условие) { прошло++; console.log('  ✅ ' + имя); }
  else { упало++; console.log('  ❌ ' + имя + (пояснение ? ' — ' + пояснение : '')); }
}

const html = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');
function функция(начало) {
  const н = html.indexOf(начало);
  if (н < 0) throw new Error('нет функции: ' + начало);
  return html.slice(н, html.indexOf('\n}\n', н) + 2);
}
const код = ['function _tursoAgo(', 'function _jobsAgoShort(', 'function renderJobsState(', 'function renderJobsPanel(',
  'function renderJobsStateOld('].map(функция).join('\n');

let узлы;
const document = { getElementById: id => (узлы[id] = узлы[id] || { innerHTML: '', textContent: '' }) };
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const renderJobsState = new Function('document', 'esc', код + '\nreturn renderJobsState;')(document, esc);

const сейчас = new Date().toISOString();
function строки(список) {
  // три ячейки на строку; первая строка — заголовок
  const ячейки = список.split('</div>').map(s => s.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').trim()).filter(Boolean);
  const out = [];
  for (let i = 3; i + 2 < ячейки.length + 1; i += 3) out.push(ячейки.slice(i, i + 3));
  return out;
}

// 1. Новый ответ сервера
function строки4(список) {
  const ячейки = список.split('</div>').map(s => s.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').trim()).filter(Boolean);
  const out = [];
  for (let i = 4; i + 3 < ячейки.length + 1; i += 4) out.push(ячейки.slice(i, i + 4));
  return out;
}
узлы = {};
renderJobsState({
  updated_at: сейчас, jobs: [
    { name: 'jobs-heartbeat', for: 'shared', label: 'daily check of this list', rank: 3, ok: true, at: сейчас, trouble: null },
    { name: 'lambda-warmup', for: 'shared', label: 'keeps the shared API warm, every 5 min', rank: 0, watch_only: true,
      numbers: { runs_24h: 288 }, at: сейчас },
    { name: 'turso-backup-actions', for: 'plantapp', label: 'nightly catalog DB copy to S3 + spares', rank: 1, ok: true,
      at: сейчас, number_text: 'copies 2' },
    { name: 'ddb-backup', for: 'shared · laptop', label: 'weekly copy of AWS user tables', rank: 1, trouble: 'silent',
      hours_ago: 290, due_hours: 192 },
    { name: 'apple-receipts-recheck', for: 'plantapp', label: 're-checks App Store refunds', rank: 0, ok: true, at: сейчас },
    { name: 'polivalka-register', for: 'polivalka', label: 'registers new devices', rank: 2, watch_only: true, trouble: 'no_runs' },
    { name: 'polivalka-auth', for: 'polivalka', label: 'device and site sign-in', rank: 2, watch_only: true, trouble: 'errors',
      numbers: { runs_24h: 9, errors_24h: 2 } },
    { name: 'aws:events/new', for: '?', label: 'runs in prod, not in registry', rank: -1, trouble: 'unregistered' },
    { name: 'old-job', for: 'plantapp', label: 'nightly photo check', rank: 3, off: '12.10.2026 решением владельца' },
  ],
});
const р = строки4(узлы['jobs-state-list'].innerHTML);
const имена = р.map(с => с[0].replace(/^\S+ /, ''));
const по = имя => р.find(с => с[0].endsWith(' ' + имя));
проверить('четыре колонки и заголовок', /job<\/div><div[^>]*>for<\/div><div[^>]*>what it does<\/div><div[^>]*>last/.test(узлы['jobs-state-list'].innerHTML));
проверить('название и шапка', /⏱ Automatic tasks · .*🔴 3 problem.*🟢 4 works.*⚪ 2 not running/.test(узлы['jobs-state-summary'].innerHTML), узлы['jobs-state-summary'].innerHTML);
проверить('problem сверху: опись первой', имена[0] === 'aws:events/new' && имена.slice(1, 3).sort().join() === 'ddb-backup,polivalka-auth', имена.join(','));
проверить('затем по важности, выключенные внизу', имена.indexOf('apple-receipts-recheck') < имена.indexOf('turso-backup-actions')
  && имена.indexOf('turso-backup-actions') < имена.indexOf('jobs-heartbeat') && имена[имена.length - 1] === 'old-job', имена.join(','));
проверить('цвета эмодзи', по('ddb-backup')[0].startsWith('🔴') && по('jobs-heartbeat')[0].startsWith('🟢')
  && по('polivalka-register')[0].startsWith('⚪') && по('old-job')[0].startsWith('⚪'));
проверить('колонка for', по('ddb-backup')[1] === 'shared · laptop' && по('polivalka-auth')[1] === 'polivalka');
проверить('число серым в конце подписи', по('turso-backup-actions')[2] === 'nightly catalog DB copy to S3 + spares · copies 2');
проверить('last: молчание, ошибки, запуски, не шёл, опись, off',
  по('ddb-backup')[3] === 'silent 12d' && по('polivalka-auth')[3] === 'errors 2/9' && по('lambda-warmup')[3] === '288 runs today'
  && по('polivalka-register')[3] === 'no runs today' && по('aws:events/new')[3] === 'not in registry' && по('old-job')[3] === 'off',
  JSON.stringify(р.map(с => с[3])));
проверить('тесный срок — 🟡, сразу после problem', (() => {
  узлы = {};
  renderJobsState({ jobs: [{ name: 'a', for: 'plantapp', label: 'x', rank: 0, ok: true, at: сейчас },
                           { name: 'b', for: 'plantapp', label: 'y', rank: 3, trouble: 'tight_threshold' },
                           { name: 'c', for: 'plantapp', label: 'z', rank: 3, trouble: 'silent', hours_ago: 50, due_hours: 24 }] });
  const р2 = строки4(узлы['jobs-state-list'].innerHTML);
  return р2[0][0].startsWith('🔴') && р2[1][0].startsWith('🟡') && р2[1][3] === 'tight threshold'
    && /🟡 1 check/.test(узлы['jobs-state-summary'].innerHTML);
})());
проверить('незнакомое состояние — красным', (() => {
  узлы = {};
  renderJobsState({ jobs: [{ name: 'x', label: 'y', rank: 0, trouble: 'что-то-новое' }] });
  return узлы['jobs-state-list'].innerHTML.includes('🔴');
})());

// 2. Старый ответ сервера — прежняя отрисовка
узлы = {};
renderJobsState({ updated_at: сейчас, jobs: [{ name: 'ddb-backup', ok: true, at: сейчас, numbers: { tables: 7 } }] });
проверить('старый ответ рисуется по-старому', узлы['jobs-state-list'].innerHTML.includes('ddb-backup')
  && !узлы['jobs-state-list'].innerHTML.includes('what it does'));

// 3. Ошибка отрисовки не валит страницу
узлы = {};
let упала = false;
try { renderJobsState({ jobs: [{ name: 'a', label: 'b', rank: 0 }, { name: 'x', label: 'y', get rank() { throw new Error('boom'); } }] }); }
catch (e) { упала = true; }
проверить('ошибка — «render error», без исключения наружу', !упала && /render error/.test(узлы['jobs-state-summary'].innerHTML));

console.log(`\n${прошло} прошло, ${упало} упало`);
process.exit(упало ? 1 : 0);
