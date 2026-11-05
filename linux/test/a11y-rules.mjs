/* An in-tree subset of axe-style accessibility rules.
 *
 * The rules run on a plain snapshot of the live page. The Electron harness
 * builds the snapshot, and the Node tests can build one by hand. The subset
 * uses the axe rule names so a reader can compare it with a full axe run.
 *
 * This is not axe-core. It checks the rules that this small local UI needs:
 * names, landmarks, heading order, labels, ARIA states, focus, target size,
 * scroll regions, and color contrast.
 */

export const VALID_ROLES = new Set([
  'alert', 'article', 'banner', 'button', 'cell', 'checkbox', 'columnheader',
  'combobox', 'complementary', 'contentinfo', 'dialog', 'document', 'form',
  'grid', 'gridcell', 'group', 'heading', 'img', 'link', 'list', 'listbox',
  'listitem', 'log', 'main', 'navigation', 'note', 'option', 'presentation',
  'progressbar', 'radio', 'radiogroup', 'region', 'row', 'rowgroup', 'search',
  'separator', 'slider', 'spinbutton', 'status', 'switch', 'tab', 'table',
  'tablist', 'tabpanel', 'textbox', 'timer', 'toolbar', 'tooltip'
]);

function violation(id, message, target) {
  return { id, message, target: target || '' };
}

function nonEmpty(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

function parseColor(value) {
  if (typeof value !== 'string') return null;
  const match = value.match(/^rgba?\(\s*(\d+(?:\.\d+)?)\s*[,\s]\s*(\d+(?:\.\d+)?)\s*[,\s]\s*(\d+(?:\.\d+)?)(?:\s*[,/]\s*(\d+(?:\.\d+)?))?\s*\)$/i);
  if (!match) return null;
  const alpha = match[4] === undefined ? 1 : Number(match[4]);
  return {
    r: Number(match[1]),
    g: Number(match[2]),
    b: Number(match[3]),
    a: alpha > 1 ? alpha / 255 : alpha
  };
}

function channel(value) {
  const scaled = value / 255;
  return scaled <= 0.03928 ? scaled / 12.92 : Math.pow((scaled + 0.055) / 1.055, 2.4);
}

function luminance(color) {
  return 0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b);
}

function blend(foreground, background) {
  const alpha = foreground.a;
  if (alpha >= 1) return foreground;
  return {
    r: foreground.r * alpha + background.r * (1 - alpha),
    g: foreground.g * alpha + background.g * (1 - alpha),
    b: foreground.b * alpha + background.b * (1 - alpha),
    a: 1
  };
}

export function contrastRatio(foreground, background) {
  const front = parseColor(foreground);
  const back = parseColor(background);
  if (!front || !back) return null;
  const solid = blend(front, back);
  const lighter = Math.max(luminance(solid), luminance(back));
  const darker = Math.min(luminance(solid), luminance(back));
  return (lighter + 0.05) / (darker + 0.05);
}

export function evaluateSnapshot(snapshot) {
  const page = snapshot && typeof snapshot === 'object' ? snapshot : {};
  const violations = [];

  if (!nonEmpty(page.lang)) {
    violations.push(violation('html-has-lang', 'The page element has no language.', 'html'));
  }
  if (!nonEmpty(page.title)) {
    violations.push(violation('document-title', 'The page has no title.', 'title'));
  }
  if (page.mainCount !== 1) {
    violations.push(violation('landmark-one-main', 'The page needs exactly one main landmark.', 'main'));
  }

  const landmarkLabels = new Set();
  for (const landmark of Array.isArray(page.landmarks) ? page.landmarks : []) {
    const label = nonEmpty(landmark.label) ? landmark.label.trim().toLowerCase() : '';
    if (!label) continue;
    if (landmarkLabels.has(label)) {
      violations.push(violation('landmark-unique', 'Two landmarks use the same name.', landmark.selector));
    }
    landmarkLabels.add(label);
  }

  for (const button of Array.isArray(page.buttons) ? page.buttons : []) {
    if (!nonEmpty(button.name)) {
      violations.push(violation('button-name', 'A button has no accessible name.', button.selector));
    }
    const width = Number(button.width);
    const height = Number(button.height);
    if (Number.isFinite(width) && Number.isFinite(height) && (width < 24 || height < 24) && button.hidden !== true) {
      violations.push(violation('target-size', 'A button is smaller than 24 by 24 pixels.', button.selector));
    }
  }

  for (const link of Array.isArray(page.links) ? page.links : []) {
    if (!nonEmpty(link.name)) {
      violations.push(violation('link-name', 'A link has no accessible name.', link.selector));
    }
  }

  for (const field of Array.isArray(page.fields) ? page.fields : []) {
    if (field.hasLabel !== true) {
      violations.push(violation('label', 'A form control has no label.', field.selector));
    }
  }

  const ids = new Set();
  for (const id of Array.isArray(page.ids) ? page.ids : []) {
    if (ids.has(id)) {
      violations.push(violation('duplicate-id', 'Two elements use the same id.', '#' + id));
    }
    ids.add(id);
  }

  for (const item of Array.isArray(page.roles) ? page.roles : []) {
    if (nonEmpty(item.role) && !VALID_ROLES.has(item.role)) {
      violations.push(violation('aria-role-valid', 'An element uses an unknown role.', item.selector));
    }
  }

  for (const item of Array.isArray(page.ariaStates) ? page.ariaStates : []) {
    const value = String(item.value);
    if (item.name === 'aria-checked') {
      if (!['true', 'false', 'mixed'].includes(value)) {
        violations.push(violation('aria-state-valid', 'An ARIA checked state is not valid.', item.selector));
      }
    } else if (!['true', 'false'].includes(value)) {
      violations.push(violation('aria-state-valid', 'An ARIA state is not true or false.', item.selector));
    }
  }

  for (const item of Array.isArray(page.tabindexes) ? page.tabindexes : []) {
    if (Number(item.value) > 0) {
      violations.push(violation('tabindex-positive', 'A positive tabindex changes the tab order.', item.selector));
    }
  }

  let previous = 0;
  for (const heading of Array.isArray(page.headings) ? page.headings : []) {
    const level = Number(heading.level);
    if (!Number.isInteger(level) || level < 1 || level > 6) continue;
    if (previous > 0 && level > previous + 1) {
      violations.push(violation('heading-order', 'A heading skips a level.', heading.selector));
    }
    previous = level;
  }

  for (const list of Array.isArray(page.lists) ? page.lists : []) {
    if (!Array.isArray(list.children)) continue;
    if (list.children.some((tag) => tag !== 'li' && tag !== 'script' && tag !== 'template')) {
      violations.push(violation('list', 'A list holds a child that is not a list item.', list.selector));
    }
  }

  for (const table of Array.isArray(page.tables) ? page.tables : []) {
    if (table.visible === true && table.headerCount > 0 && table.scopedHeaders !== table.headerCount) {
      violations.push(violation('table-headers', 'A table header has no scope.', table.selector));
    }
  }

  for (const image of Array.isArray(page.images) ? page.images : []) {
    if (image.decorative !== true && !nonEmpty(image.alt)) {
      violations.push(violation('image-alt', 'An image has no text alternative.', image.selector));
    }
  }

  for (const item of Array.isArray(page.scrollRegions) ? page.scrollRegions : []) {
    if (Number(item.tabindex) < 0) {
      violations.push(violation('scrollable-region-focusable', 'A scroll region is not reachable by keyboard.', item.selector));
    }
  }

  for (const item of Array.isArray(page.ariaHiddenFocus) ? page.ariaHiddenFocus : []) {
    if (item.focusable === true) {
      violations.push(violation('aria-hidden-focus', 'An aria-hidden element holds a focusable control.', item.selector));
    }
  }

  for (const item of Array.isArray(page.contrast) ? page.contrast : []) {
    const ratio = contrastRatio(item.color, item.background);
    if (ratio === null) continue;
    const minimum = item.large === true ? 3 : 4.5;
    if (ratio + 0.01 < minimum) {
      violations.push(violation('color-contrast', 'Text contrast is ' + ratio.toFixed(2) + ':1.', item.selector));
    }
  }

  for (const item of Array.isArray(page.focusVisible) ? page.focusVisible : []) {
    if (!nonEmpty(item.tag)) continue;
    const width = Number(String(item.outlineWidth || '0px').replace('px', ''));
    if (item.outlineStyle === 'none' || !Number.isFinite(width) || width < 2) {
      violations.push(violation('focus-visible', 'A focused control has no visible outline.', item.selector));
    }
  }

  return violations;
}
