import test from 'node:test';
import assert from 'node:assert/strict';
import { contrastRatio, evaluateSnapshot } from './a11y-rules.mjs';

function cleanSnapshot() {
  return {
    lang: 'en',
    title: 'HotspotShade',
    mainCount: 1,
    landmarks: [
      { selector: 'nav', label: 'Primary' },
      { selector: 'aside', label: 'Sidebar' }
    ],
    buttons: [
      { selector: '#one', name: 'One', width: 120, height: 32 },
      { selector: '#two', name: 'Two', width: 32, height: 32 }
    ],
    links: [{ selector: '.skip', name: 'Skip to content' }],
    fields: [{ selector: '#ping', hasLabel: true }],
    ids: ['one', 'two'],
    roles: [{ selector: 'main', role: 'main' }],
    ariaStates: [{ selector: '#tab', name: 'aria-selected', value: 'true' }],
    tabindexes: [{ selector: '#main', value: -1 }],
    headings: [{ selector: 'h1', level: 1 }, { selector: 'h2', level: 2 }],
    lists: [{ selector: 'ul', children: ['li', 'li'] }],
    tables: [{ selector: 'table', visible: true, headerCount: 2, scopedHeaders: 2 }],
    images: [{ selector: 'svg', decorative: true, alt: '' }],
    scrollRegions: [{ selector: '.table-scroll', tabindex: 0 }],
    ariaHiddenFocus: [{ selector: '.icon', focusable: false }],
    contrast: [{ selector: 'body', color: 'rgb(20, 20, 20)', background: 'rgb(255, 255, 255)', large: false }],
    focusVisible: [{ selector: '#one', tag: 'BUTTON', outlineStyle: 'solid', outlineWidth: '2px' }]
  };
}

test('a clean snapshot has no violation', () => {
  assert.deepEqual(evaluateSnapshot(cleanSnapshot()), []);
});

test('names, labels, and landmarks are required', () => {
  const page = cleanSnapshot();
  page.lang = '';
  page.title = ' ';
  page.mainCount = 0;
  page.buttons[0].name = '';
  page.links[0].name = '';
  page.fields[0].hasLabel = false;
  page.landmarks = [{ selector: 'nav', label: 'Same' }, { selector: 'aside', label: 'Same' }];
  const ids = evaluateSnapshot(page).map((item) => item.id);
  for (const id of ['html-has-lang', 'document-title', 'landmark-one-main', 'button-name', 'link-name', 'label', 'landmark-unique']) {
    assert.ok(ids.includes(id), id);
  }
});

test('ARIA, tab order, headings, lists, and tables are checked', () => {
  const page = cleanSnapshot();
  page.ids.push('one');
  page.roles.push({ selector: 'div', role: 'madeup' });
  page.ariaStates.push({ selector: '#toggle', name: 'aria-pressed', value: 'yes' });
  page.tabindexes.push({ selector: '#first', value: 2 });
  page.headings.push({ selector: 'h4', level: 4 });
  page.lists.push({ selector: 'ol', children: ['li', 'div'] });
  page.tables.push({ selector: 'table.two', visible: true, headerCount: 3, scopedHeaders: 1 });
  const ids = evaluateSnapshot(page).map((item) => item.id);
  for (const id of ['duplicate-id', 'aria-role-valid', 'aria-state-valid', 'tabindex-positive', 'heading-order', 'list', 'table-headers']) {
    assert.ok(ids.includes(id), id);
  }
});

test('target size, contrast, focus, scroll, and aria-hidden focus are checked', () => {
  const page = cleanSnapshot();
  page.buttons.push({ selector: '#tiny', name: 'Tiny', width: 16, height: 16 });
  page.contrast.push({ selector: '.muted', color: 'rgb(180, 180, 180)', background: 'rgb(255, 255, 255)', large: false });
  page.contrast.push({ selector: '.large', color: 'rgb(120, 120, 120)', background: 'rgb(255, 255, 255)', large: true });
  page.focusVisible = [{ selector: '#one', tag: 'BUTTON', outlineStyle: 'none', outlineWidth: '0px' }];
  page.scrollRegions.push({ selector: '.scroll', tabindex: -1 });
  page.ariaHiddenFocus.push({ selector: '.hidden-button', focusable: true });
  const ids = evaluateSnapshot(page).map((item) => item.id);
  for (const id of ['target-size', 'color-contrast', 'focus-visible', 'scrollable-region-focusable', 'aria-hidden-focus']) {
    assert.ok(ids.includes(id), id);
  }
});

test('contrast ratios use WCAG luminance', () => {
  assert.equal(Math.round(contrastRatio('rgb(0, 0, 0)', 'rgb(255, 255, 255)')), 21);
  assert.equal(Math.round(contrastRatio('rgb(119, 119, 119)', 'rgb(255, 255, 255)')), 4);
  assert.equal(contrastRatio('not a color', 'rgb(255, 255, 255)'), null);
});
