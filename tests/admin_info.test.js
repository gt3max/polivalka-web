/**
 * Значок ⓘ: стоит у каждой карточки, открывает по одному, текст есть у всех.
 *
 * 🔴 Главная проверка здесь — ПОЛНОТА. Пояснения в панели и раньше были, но
 * случайно: у одной карточки приписка внизу, у другой строка в шапке, у
 * остальных ничего. Если не стеречь полноту, через месяц половина карточек
 * снова окажется без объяснения — и владелец опять будет гадать, поломка перед
 * ним или норма.
 *
 * Браузер не нужен: дерево документа подменено крошечной заглушкой.
 *
 * Запуск: node tests/admin_info.test.js
 */
const fs = require('fs');
const path = require('path');
const { поставить, ТЕКСТЫ, ключ } = require('../admin-info.js');

let прошло = 0, упало = 0;
function проверить(имя, условие, пояснение) {
  if (условие) { прошло++; console.log('  ✅ ' + имя); }
  else { упало++; console.log('  ❌ ' + имя + (пояснение ? ' — ' + пояснение : '')); }
}

/** Заглушка дерева: ровно то, чем пользуется admin-info.js. */
function узел(имя) {
  return {
    tagName: имя, id: '', className: '', type: '', textContent: '',
    //: 🔴 Заглушка стиля повторяет браузер: запись в cssText выставляет и
    //: отдельные свойства. Без этого «сначала закрыто» падало на верном коде —
    //: тест проверял не то, что делает страница.
    style: (function () {
      var с = { position: '', display: '' };
      Object.defineProperty(с, 'cssText', {
        get() { return с._текст || ''; },
        set(v) {
          с._текст = v;
          String(v).split(';').forEach(function (пара) {
            var i = пара.indexOf(':');
            if (i < 0) return;
            var имя = пара.slice(0, i).trim(), знач = пара.slice(i + 1).trim();
            if (имя === 'display') с.display = знач;
            if (имя === 'position') с.position = знач;
          });
        },
      });
      return с;
    })(),
    дети: [], слушатели: {},
    setAttribute() {}, 
    addEventListener(с, f) { (this.слушатели[с] = this.слушатели[с] || []).push(f); },
    нажать() { (this.слушатели.click || []).forEach(f => f({ stopPropagation() {} })); },
    insertBefore(н) { this.дети.unshift(н); },
    querySelector(сел) {
      if (сел === '.инфо-значок') return this.дети.find(д => д.className === 'инфо-значок') || null;
      if (сел === 'h2, h3') return this._заголовок || null;
      return null;
    },
    querySelectorAll(сел) {
      const класс = сел.replace('.', '');
      const из = [];
      const обойти = (у) => { u_children(у).forEach(д => { if (д.className === класс) из.push(д); обойти(д); }); };
      const u_children = (у) => у.дети || [];
      обойти(this);
      return из;
    },
  };
}

function документ(карточки) {
  const корень = узел('body');
  корень.createElement = узел;
  корень.дети = карточки;
  корень.__инфо_закрывалка = false;
  корень.querySelectorAll = function (сел) {
    if (сел === '.card') return карточки;
    const класс = сел.replace('.', '');
    const из = [];
    карточки.forEach(к => (к.дети || []).forEach(д => { if (д.className === класс) из.push(д); }));
    return из;
  };
  корень.addEventListener = function () {};
  return корень;
}

function карточка(ид, заголовок) {
  const к = узел('div');
  к.className = 'card';
  к.id = ид || '';
  if (заголовок) { const h = узел('h3'); h.textContent = заголовок; к._заголовок = h; }
  return к;
}

console.log('ЗНАЧОК ⓘ В АДМИНКЕ (браузер не нужен)\n');

// 1. значок появляется у карточки с известным опознавателем
{
  const к = карточка('turso-card');
  const д = документ([к]);
  const n = поставить(д);
  проверить('значок поставлен', n === 1 && !!к.querySelector('.инфо-значок'));
  проверить('текст положен рядом', к.дети.some(x => x.className === 'инфо-текст' && x.textContent.length > 40));
}

// 2. нажатие открывает, второе закрывает
{
  const к = карточка('turso-card');
  const д = документ([к]);
  поставить(д);
  const значок = к.дети.find(x => x.className === 'инфо-значок');
  const поле = к.дети.find(x => x.className === 'инфо-текст');
  проверить('сначала закрыто', поле.style.display === 'none');
  значок.нажать();
  проверить('нажатие открывает', поле.style.display === 'block');
  значок.нажать();
  проверить('второе нажатие закрывает', поле.style.display === 'none');
}

// 3. 🔴 открыто не больше одного
{
  const а = карточка('turso-card'), б = карточка('cloudinary-card');
  const д = документ([а, б]);
  поставить(д);
  а.дети.find(x => x.className === 'инфо-значок').нажать();
  б.дети.find(x => x.className === 'инфо-значок').нажать();
  const открытых = [а, б].filter(к => к.дети.find(x => x.className === 'инфо-текст').style.display === 'block');
  проверить('открыто ровно одно пояснение', открытых.length === 1, 'открыто: ' + открытых.length);
}

// 4. повторный проход не плодит значки
{
  const к = карточка('turso-card');
  const д = документ([к]);
  поставить(д); поставить(д);
  const значков = к.дети.filter(x => x.className === 'инфо-значок').length;
  проверить('второй проход не добавляет значок', значков === 1, 'значков: ' + значков);
}

// 5. 🔴 ПОЛНОТА: у каждой карточки панели есть текст
{
  const html = fs.readFileSync(path.join(__dirname, '..', 'admin.html'), 'utf8');
  const из_панели = [];
  const рег = /<div class="card"([^>]*)>/g;
  let m;
  while ((m = рег.exec(html))) {
    const хвост = html.slice(m.index, m.index + 900);
    const ид = /id="([^"]+)"/.exec(m[1]);
    const заг = /<h[23][^>]*>([\s\S]*?)<\/h[23]>/.exec(хвост);
    из_панели.push(ид ? ид[1] : (заг ? заг[1].replace(/<[^>]+>/g, '').trim() : '(?)'));
  }
  const без = из_панели.filter(к => !ТЕКСТЫ[к]);
  проверить('у каждой карточки панели есть пояснение', без.length === 0,
    'без текста: ' + JSON.stringify(без));
  проверить('карточек найдено больше двадцати', из_панели.length > 20, 'нашли: ' + из_панели.length);
}

console.log('\nитог: ' + прошло + ' прошло, ' + упало + ' упало');
process.exit(упало ? 1 : 0);
