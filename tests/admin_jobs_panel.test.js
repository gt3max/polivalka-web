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
узлы = {};
renderJobsState({
  updated_at: сейчас, jobs: [
    { name: 'jobs-heartbeat', label: 'daily check of this list', rank: 3, ok: true, at: сейчас, trouble: null },
    { name: 'lambda-warmup', label: 'keeps the shared API warm, every 5 min', rank: 0, watch_only: true },
    { name: 'turso-backup-actions', label: 'nightly catalog DB copy to S3 + spares', rank: 1, ok: true, at: сейчас,
      number_text: 'copies 2' },
    { name: 'ddb-backup', label: 'weekly copy of AWS user tables', rank: 1, trouble: 'silent', hours_ago: 290, due_hours: 192 },
    { name: 'apple-receipts-recheck', label: 're-checks App Store refunds', rank: 0, ok: true, at: сейчас },
    { name: 'old-job', label: 'nightly photo check', rank: 3, off: '12.10.2026 решением владельца' },
  ],
});
const р = строки(узлы['jobs-state-list'].innerHTML);
const имена = р.map(с => с[0].replace(/^[●○] /, ''));
проверить('три колонки и заголовок', /job<\/div><div[^>]*>what it does<\/div><div[^>]*>last/.test(узлы['jobs-state-list'].innerHTML));
проверить('беда первой', имена[0] === 'ddb-backup', имена.join(','));
проверить('деньги раньше данных и сторожей', имена.indexOf('apple-receipts-recheck') < имена.indexOf('turso-backup-actions')
  && имена.indexOf('turso-backup-actions') < имена.indexOf('jobs-heartbeat'), имена.join(','));
проверить('наблюдение после живых, выключенные в самом низу', имена.indexOf('lambda-warmup') > имена.indexOf('jobs-heartbeat')
  && имена[имена.length - 1] === 'old-job', имена.join(','));
проверить('число серым в конце подписи', р.find(с => с[0].includes('turso-backup-actions'))[1] === 'nightly catalog DB copy to S3 + spares · copies 2');
проверить('молчание коротко в колонке last', р.find(с => с[0].includes('ddb-backup'))[2] === 'silent 12d');
проверить('наблюдение и выключено подписаны', р.find(с => с[0].includes('lambda-warmup'))[2] === 'watch-only'
  && р.find(с => с[0].includes('old-job'))[2] === 'off');
проверить('шапка считает только живые', /Jobs <b>3\/4<\/b> ok/.test(узлы['jobs-state-summary'].innerHTML), узлы['jobs-state-summary'].innerHTML);
проверить('незнакомая беда — красным, не зелёным', (() => {
  узлы = {};
  renderJobsState({ jobs: [{ name: 'x', label: 'y', rank: 0, trouble: 'unregistered' }] });
  return узлы['jobs-state-list'].innerHTML.includes('#f44');
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
