/**
 * Карточка «Modules»: Поливалка — модуль как все, прошивка — её подмодуль, без перечня версий по устройствам.
 *
 * 🔴 05.11.2026. Карточка рисовала прошивку отдельной строкой с хвостом «devices: 2× 1.0.199, 1× 1.0.213, …» —
 * данные парка вместо номера модуля. В реестре (plantapp documentation/modules.json) firmware.parent = polivalka,
 * у модуля одна серия номеров. Стережём вид: никаких «devices:», подмодуль под родителем.
 *
 * Браузер не нужен: функция берётся из admin.html, дерево и сеть подменены.
 * Запуск: node tests/admin_modules.test.js
 */
const fs = require('fs');
const path = require('path');

let прошло = 0, упало = 0;
function проверить(имя, условие, пояснение) {
  if (условие) { прошло++; console.log('  ✅ ' + имя); }
  else { упало++; console.log('  ❌ ' + имя + (пояснение ? ' — ' + пояснение : '')); }
}

const html = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');
const н = html.indexOf('async function loadModules(){');
const к = html.indexOf('\n}\n', н);
const код = html.slice(н, к + 2);

const узлы = {};
const document = { getElementById: id => (узлы[id] = узлы[id] || { innerHTML: '', textContent: '', disabled: false }) };
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const API = { cloudBase: 'https://x', getAuthHeaders: () => ({}) };
const allDevicesData = [{ firmware_version: 'v1.0.199' }, { firmware_version: 'v1.0.217' }];
const ответ = {
  modules: { library: '1.0.4', my_plants: '1.0.3', polivalka: '1.0.12', firmware: '1.0.217' },
  modules_detached: ['firmware', 'polivalka'], modules_off: [], modules_rolled_back: {},
  modules_live: { firmware: { live: '1.0.217', prev: '1.0.214' } }, modules_app: {}, lambda_version: 36,
};
const fetch = async () => ({ ok: true, json: async () => ответ });

(async () => {
  const loadModules = new Function('document', 'esc', 'API', 'allDevicesData', 'fetch',
    код + '\nreturn loadModules;')(document, esc, API, allDevicesData, fetch);
  await loadModules();
  const список = узлы['modules-list'].innerHTML;
  const строки = список.split('</div>').map(s => s.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').trim()).filter(Boolean);
  проверить('нет перечня версий по устройствам', !/devices:/.test(список) && !/\d+× /.test(список), список);
  const и_пол = строки.findIndex(s => s.startsWith('polivalka 1.0.12'));
  const и_прош = строки.findIndex(s => s.includes('└ firmware 1.0.217'));
  проверить('Поливалка — строкой модуля', и_пол >= 0, строки.join(' | '));
  проверить('прошивка — подмодулем сразу под Поливалкой', и_прош === и_пол + 1, строки.join(' | '));
  проверить('откат / прежний номер у прошивки остаётся', строки[и_прош] && строки[и_прош].includes('(was 1.0.214)'));
  проверить('обычные модули не тронуты', строки.some(s => s.startsWith('my_plants 1.0.3 · —')));
  console.log(`\n${прошло} прошло, ${упало} упало`);
  process.exit(упало ? 1 : 0);
})();
