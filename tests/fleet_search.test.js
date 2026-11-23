/**
 * Fleet «Device List» search.
 *
 * 🔴 Why (23.11.2026). The owner typed a board's ID into the search and got nothing: the card title shows
 * `device_id`, the search compared only `device.name` (by default "Polivalka" on every board). Four repaints
 * (list load, 5-min auto-refresh, Refresh, Refresh All) drew every board ignoring the filters, and an empty
 * result said "No devices yet". Rules taken from the PlantApp library search (plantapp
 * documentation/PlantApp_Description.md §5.1): several channels, normalisation, every word must match,
 * next step (wrong keyboard layout) only on zero, no fuzzy guessing of an ID. Plan review:
 * Polivalka documentation/Fable/2026-11-23_fleet_search_plan_review.md.
 *
 * Entry point is filterDevices() — it exists in the old and the new page, so the old page fails by
 * BEHAVIOUR ("5285A1" → 0 boards), not by "function not found". No browser needed.
 *
 * Run: node tests/fleet_search.test.js
 */
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'fleet.html'), 'utf8');

function функция(имя, обязательна) {
  const i = html.indexOf('\nfunction ' + имя + '(');
  if (i < 0) {
    if (обязательна) throw new Error('fleet.html: not found function ' + имя);
    return '';
  }
  const хвост = html.slice(i + 1);
  const м = /\n\}\n/.exec(хвост);
  return хвост.slice(0, м.index + 3);
}

// The search block (new page): helpers and their tables live between these two markers.
function блокПоиска() {
  const нач = html.indexOf('// ── Device List search');
  const кон = html.indexOf('// ── end Device List search');
  return нач >= 0 && кон > нач ? html.slice(нач, кон) : '';
}

const код = [блокПоиска(), функция('timerWetWarn', true), функция('filterDevices', true),
  функция('applyFilters', false)].join('\n');

function прогнать(devices, filters) {
  const поля = {
    'search-input': { value: filters.search || '' },
    'location-filter': { value: filters.location || '' },
    'status-filter': { value: filters.status || '' },
    'mode-filter': { value: filters.mode || '' },
  };
  const документ = {
    getElementById: id => поля[id] || (поля[id] = { value: '', textContent: '', style: {}, hidden: false }),
  };
  const s = { out: null, document: документ, devices };
  new Function('sandbox', 'const document = sandbox.document; let allDevices = sandbox.devices;'
    + ' let currentView = "list"; function renderDevices(d) { sandbox.out = d; }\n'
    + код + '\nfilterDevices();')(s);
  return (s.out || []).map(d => d.device_id.replace('Polivalka-', '')).sort().join(',');
}

const ПЛАТЫ = () => [
  { device_id: 'Polivalka-5285A1', name: 'Polivalka', location: 'Home', room: 'Kitchen', online: true,
    mode: 'sensor', warnings: [], battery_pct: null, moisture_pct: 50 },
  { device_id: 'Polivalka-BC67E9', name: 'Фикус', location: 'Office', room: 'Room', online: false,
    mode: 'timer', warnings: [], battery_pct: null, moisture_pct: 40 },
  { device_id: 'Polivalka-EC7239', name: 'Monstera', location: 'Home', room: 'Living room', online: true,
    mode: 'manual', warnings: [], battery_pct: null, moisture_pct: 45 },
];
// A board with no name and no place: the old page crashed on it (`device.name.toLowerCase()`), so it is
// kept out of the main list — otherwise that crash hides the main defect (search ignores the ID).
const БЕЗ_ИМЕНИ = () => ПЛАТЫ().concat([{ device_id: 'Polivalka-0A1B2C', online: true, mode: 'sensor',
  warnings: [], battery_pct: null, moisture_pct: null }]);

let прошло = 0, упало = 0;
function проверить(имя, ожидание, фильтры, платы) {
  let получено;
  try { получено = прогнать((платы || ПЛАТЫ)(), фильтры); } catch (e) { получено = 'ERROR ' + e.message; }
  if (получено === ожидание) { прошло++; console.log('  ✅ ' + имя); }
  else { упало++; console.log('  ❌ ' + имя + ' — expected [' + ожидание + '], got [' + получено + ']'); }
}
function верно(имя, условие, пояснение) {
  if (условие) { прошло++; console.log('  ✅ ' + имя); }
  else { упало++; console.log('  ❌ ' + имя + (пояснение ? ' — ' + пояснение : '')); }
}

const ВСЕ = '5285A1,BC67E9,EC7239';

console.log('\nBy what is on the card (ID):');
проверить('🔴 short ID', '5285A1', { search: '5285A1' });
проверить('short ID, lower case', '5285A1', { search: '5285a1' });
проверить('full ID', '5285A1', { search: 'Polivalka-5285A1' });
проверить('ID with a space instead of the dash', '5285A1', { search: 'polivalka 5285a1' });
проверить('ID with a dash inside', '5285A1', { search: '5285-a1' });
проверить('spaces around', '5285A1', { search: '  5285A1  ' });
проверить('part of the ID', '5285A1', { search: '5285' });
проверить('board without a name or place — no crash', '0A1B2C', { search: '0a1b2c' }, БЕЗ_ИМЕНИ);

console.log('\nBy name and place:');
проверить('name (Cyrillic)', 'BC67E9', { search: 'фикус' });
проверить('name, any case', 'BC67E9', { search: 'ФИКУС' });
проверить('name (Latin)', 'EC7239', { search: 'monstera' });
проверить('room', '5285A1', { search: 'kitchen' });
проверить('location', 'BC67E9', { search: 'office' });
проверить('placeholder room "Room" is not a match', 'EC7239', { search: 'room' });
проверить('accents ignored ("cafe" finds "Café")', 'C0FFEE', { search: 'cafe' },
  () => ПЛАТЫ().concat([{ device_id: 'Polivalka-C0FFEE', name: 'Café', online: true, mode: 'sensor',
    warnings: [], battery_pct: null, moisture_pct: 40 }]));

console.log('\nSeveral words — every one must match:');
проверить('room + ID', '5285A1', { search: 'kitchen 5285' });
проверить('words from different boards → nothing', '', { search: '5285 office' });

console.log('\nWrong keyboard layout (only when nothing found):');
проверить('"monstera" typed on the Russian layout', 'EC7239', { search: 'ьщтыеукф' });
проверить('"фикус" typed on the Latin layout', 'BC67E9', { search: 'abrec' });

console.log('\nEmpty and nothing:');
проверить('empty search → all', ВСЕ, { search: '' });
проверить('only spaces → all', ВСЕ, { search: '   ' });
проверить('nothing matches → none', '', { search: 'zzzz' });
проверить('with a nameless board, empty search → all', '0A1B2C,' + ВСЕ, { search: '' }, БЕЗ_ИМЕНИ);

console.log('\nOther filters as before:');
проверить('status Offline', 'BC67E9', { status: 'offline' });
проверить('mode Timer', 'BC67E9', { mode: 'timer' });
проверить('location Home', '5285A1,EC7239', { location: 'Home' });
проверить('search + status together', '', { search: 'фикус', status: 'online' });

console.log('\nOne way to draw the list:');
const вызовы = html.split('\n').filter(с => /renderDevices\(/.test(с) && !/^\s*\/\//.test(с)
  && !/function renderDevices\(/.test(с) && !/\/\/.*renderDevices\(/.test(с.replace(/^[^/]*renderDevices\(/, '')));
верно('🔴 renderDevices( is called once, inside applyFilters',
  вызовы.length === 1 && /function applyFilters\([^]*?renderDevices\(/.test(функция('applyFilters', false)),
  'calls: ' + вызовы.map(с => с.trim()).join(' | '));
верно('🔴 empty result is not "No devices yet"', /No devices match the current filters/.test(html),
  'an empty search result would say "No devices yet"');

console.log('\n' + (упало ? `❌ ${упало} failed, ${прошло} passed` : `✅ all passed (${прошло})`));
process.exit(упало ? 1 : 0);
