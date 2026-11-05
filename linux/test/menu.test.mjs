import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createTemplate } = require('../src/main/menu.js');

function helpLabels(engineMode) {
  const template = createTemplate({
    app: { quit() {} },
    window: null,
    engineMode,
    sendCommand() {}
  });
  const help = template.find((item) => item.label === 'Help');
  return help.submenu.map((item) => item.label || item.type);
}

test('the Help menu hides the demo scenario in engine mode', () => {
  const demo = helpLabels(false);
  const engine = helpLabels(true);
  assert.ok(demo.includes('Demo Scenarios'));
  assert.ok(demo.includes('Limitations'));
  assert.ok(engine.includes('Limitations'));
  assert.ok(!engine.includes('Demo Scenarios'));
  assert.ok(engine.includes('About HotspotShade'));
});
