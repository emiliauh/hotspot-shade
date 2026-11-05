// Test-only script for the hidden webview smoke test.
//
// The script runs inside the real Tauri webview after the production fetch
// shim and the production page. It checks the demo labels, navigation, native
// menu bridge, themes, layout bounds, and the demo API. It sends one report to
// the test binary. It makes no request outside the webview.
(function () {
  'use strict';

  var PAGE_DEADLINE_MS = 20000;
  var FETCH_DEADLINE_MS = 8000;
  var POLL_MS = 100;
  var started = Date.now();
  var errors = [];
  var finished = false;

  window.addEventListener('error', function (event) {
    errors.push('error: ' + (event && event.message ? event.message : 'unknown'));
  });
  window.addEventListener('unhandledrejection', function (event) {
    var reason = event && event.reason;
    errors.push('rejection: ' + (reason && reason.message ? reason.message : String(reason)));
  });

  function report(payload) {
    try {
      window.__TAURI_INTERNALS__.invoke('smoke_report', { payload: payload }).catch(function (error) {
        console.error('WEBVIEW SMOKE: report IPC failed:', error);
      });
    } catch (error) {
      console.error('WEBVIEW SMOKE: report IPC failed:', error);
    }
  }

  function progress(name) {
    report({ partial: true, name: name, at: Date.now() });
  }

  function note(checks, failures, name, pass, detail) {
    checks.push({ name: name, pass: !!pass, detail: detail || '' });
    if (!pass) failures.push(name + (detail ? ': ' + detail : ''));
  }

  function element(id) {
    return document.getElementById(id);
  }

  function visible(node) {
    if (!node) return false;
    var style = getComputedStyle(node);
    var rect = node.getBoundingClientRect();
    return node.hidden === false && style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0;
  }

  function findCredentialKey(value, path) {
    if (!value || typeof value !== 'object') return null;
    if (Array.isArray(value)) {
      for (var index = 0; index < value.length; index += 1) {
        var item = findCredentialKey(value[index], path + '[' + index + ']');
        if (item) return item;
      }
      return null;
    }
    var keys = Object.keys(value);
    for (var keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      var key = keys[keyIndex];
      var lower = key.toLowerCase();
      if (lower.indexOf('token') !== -1 ||
          lower.indexOf('password') !== -1 ||
          lower.indexOf('authorization') !== -1 ||
          lower.indexOf('secret') !== -1) {
        return path + '.' + key;
      }
      var nested = findCredentialKey(value[key], path + '.' + key);
      if (nested) return nested;
    }
    return null;
  }

  function externalAssets() {
    var found = [];
    var nodes = document.querySelectorAll('[src], [href]');
    for (var index = 0; index < nodes.length; index += 1) {
      var raw = nodes[index].getAttribute('src') || nodes[index].getAttribute('href');
      if (!raw || raw.charAt(0) === '#') continue;
      try {
        var url = new URL(raw, location.href);
        if (url.protocol === 'http:' || url.protocol === 'https:') found.push(raw);
      } catch (error) {
        found.push(raw);
      }
    }
    return found;
  }

  function withDeadline(promise, milliseconds) {
    return new Promise(function (resolve, reject) {
      var timer = setTimeout(function () {
        reject(new Error('The request did not finish within ' + milliseconds + ' ms.'));
      }, milliseconds);
      promise.then(function (value) {
        clearTimeout(timer);
        resolve(value);
      }, function (error) {
        clearTimeout(timer);
        reject(error);
      });
    });
  }

  function waitFor(predicate, milliseconds, label) {
    var begun = Date.now();
    return new Promise(function (resolve, reject) {
      function poll() {
        var value = false;
        try {
          value = predicate();
        } catch (error) {
          value = false;
        }
        if (value) {
          resolve(value);
          return;
        }
        if (Date.now() - begun > milliseconds) {
          reject(new Error('Timed out waiting for ' + label + '.'));
          return;
        }
        setTimeout(poll, 100);
      }
      poll();
    });
  }

  function textOf(node) {
    return String((node && node.textContent) || '').trim();
  }

  function resizeTo(width, height) {
    return withDeadline(window.__TAURI_INTERNALS__.invoke('smoke_resize', {
      width: width,
      height: height
    }), 5000).then(function () {
      return new Promise(function (resolve) {
        setTimeout(resolve, 300);
      });
    });
  }

  function measureAt(checks, failures, label, width, height, expectedSidebar) {
    return resizeTo(width, height).then(function () {
      // The media query can apply a little after the resize on a slow runner.
      return waitFor(function () {
        return Math.abs(document.querySelector('.sidebar').getBoundingClientRect().width -
          expectedSidebar) <= 4;
      }, 3000, 'the sidebar width').catch(function () {
        return false;
      });
    }).then(function () {
      var sidebar = document.querySelector('.sidebar').getBoundingClientRect();
      var view = element('view-dashboard').getBoundingClientRect();
      note(checks, failures, label + '_window_size',
        Math.abs(window.innerWidth - width) <= 4,
        window.innerWidth + 'x' + window.innerHeight);
      note(checks, failures, label + '_sidebar',
        Math.abs(sidebar.width - expectedSidebar) <= 4,
        String(Math.round(sidebar.width)));
      note(checks, failures, label + '_content_bounded',
        view.width > 400 && view.width <= 721,
        String(Math.round(view.width)));
      note(checks, failures, label + '_no_horizontal_overflow',
        document.documentElement.scrollWidth <= window.innerWidth + 1,
        document.documentElement.scrollWidth + ' > ' + window.innerWidth);
      if (expectedSidebar > 100) {
        note(checks, failures, label + '_demo_label_visible', visible(element('demoPill')));
      }
      note(checks, failures, label + '_demo_banner_visible', visible(element('demoBanner')));
    });
  }

  function menuChecks(checks, failures) {
    progress('menu_start');
    return withDeadline(window.__TAURI_INTERNALS__.invoke('smoke_menu', {
      id: 'view.settings'
    }), 5000).then(function () {
      return waitFor(function () {
        return visible(element('view-settings'));
      }, 3000, 'the native Settings action');
    }).then(function () {
      return withDeadline(window.__TAURI_INTERNALS__.invoke('smoke_menu', {
        id: 'view.dashboard'
      }), 5000);
    }).then(function () {
      return waitFor(function () {
        return visible(element('view-dashboard'));
      }, 3000, 'the native Dashboard action');
    }).then(function () {
      note(checks, failures, 'native_menu_dispatch', true);
      progress('menu_done');
    }).catch(function (error) {
      note(checks, failures, 'native_menu_dispatch', false,
        error && error.message ? error.message : String(error));
    });
  }

  function layoutSizes(checks, failures) {
    progress('layout_sizes_start');
    return measureAt(checks, failures, 'layout_1440', 1440, 1000, 200)
      .then(function () {
        return measureAt(checks, failures, 'layout_1100', 1100, 900, 200);
      })
      .then(function () {
        return measureAt(checks, failures, 'layout_780', 780, 560, 64);
      })
      .then(function () {
        return resizeTo(960, 700);
      })
      .then(function () {
        progress('layout_sizes_done');
      })
      .catch(function (error) {
        note(checks, failures, 'layout_sizes', false,
          error && error.message ? error.message : String(error));
      });
  }

  function actionChecks(checks, failures) {
    var primary = element('primaryAction');
    var secondary = element('secondaryAction');
    progress('actions_start');
    return waitFor(function () {
      return visible(primary) && textOf(primary) === 'Pair with source device';
    }, 5000, 'the Pair action').then(function () {
      progress('actions_pair_click');
      primary.click();
      return waitFor(function () {
        return visible(element('pairCodeBlock')) && textOf(element('pairCode')) === '123 456';
      }, 6000, 'the demo pairing code');
    }).then(function () {
      note(checks, failures, 'demo_pair_code', true);
      progress('actions_code_seen');
      return waitFor(function () {
        return visible(primary) && textOf(primary) === 'Turn on';
      }, 35000, 'the Turn on action after pairing');
    }).then(function () {
      note(checks, failures, 'demo_pair_completes', true);
      note(checks, failures, 'demo_turn_on_available', true);
      progress('actions_turn_on_click');
      primary.click();
      return waitFor(function () {
        return textOf(element('dashboardTitle')) === 'On' &&
          visible(primary) && textOf(primary) === 'Turn off';
      }, 10000, 'the running state');
    }).then(function () {
      note(checks, failures, 'demo_turn_on_result', true);
      note(checks, failures, 'demo_ping_line',
        textOf(element('connectionDetails')).indexOf('Ping is on.') !== -1);
      progress('actions_turn_off_click');
      primary.click();
      return waitFor(function () {
        return visible(primary) && textOf(primary) === 'Turn on';
      }, 10000, 'the stopped state');
    }).then(function () {
      note(checks, failures, 'demo_turn_off_result', true);
      progress('actions_stopped');
      return waitFor(function () {
        return visible(secondary) && textOf(secondary) === 'Forget this source device';
      }, 5000, 'the Forget action');
    }).then(function () {
      progress('actions_forget_click');
      secondary.click();
      return waitFor(function () {
        return textOf(element('dashboardTitle')) === 'Not paired' &&
          visible(primary) && textOf(primary) === 'Pair with source device';
      }, 10000, 'the forgotten state');
    }).then(function () {
      note(checks, failures, 'demo_forget_result', true);
      progress('actions_done');
    }).catch(function (error) {
      note(checks, failures, 'demo_action_sequence', false,
        error && error.message ? error.message : String(error));
      progress('actions_failed');
    });
  }

  function finish(checks, failures) {
    if (finished) return;
    finished = true;
    if (errors.length) {
      failures.push('page errors: ' + errors.join(' | '));
    }
    report({
      pass: failures.length === 0,
      checks: checks,
      failures: failures,
      userAgent: navigator.userAgent,
      viewport: window.innerWidth + 'x' + window.innerHeight
    });
  }

  function modelChecks(checks, failures) {
    var model = window.HotspotShadeModel;
    note(checks, failures, 'model_loaded', !!model && typeof model.deriveDashboard === 'function');
    if (!model) return;

    var base = {
      demo: true,
      running: false,
      paired: false,
      phone: { state: 'unpaired', message: 'Not paired. Open HotspotShade on your source device, then pair.' },
      forget: { state: 'none' },
      last_stop_message: null
    };
    var unpaired = model.deriveDashboard({
      status: base, hasStatus: true, pair: { state: 'idle' },
      freshness: 'fresh', nowSeconds: 100
    });
    note(checks, failures, 'model_unpaired_action',
      unpaired.title === 'Not paired' && unpaired.primary && unpaired.primary.id === 'pair');

    var running = model.deriveDashboard({
      status: {
        demo: true, running: true, mode: 'phone', paired: true, icmp_enabled: true,
        phone: { state: 'connected', message: 'Connected to the source device.', connections: 2 },
        forget: { state: 'none' }, last_stop_message: null
      },
      hasStatus: true, pair: { state: 'paired' }, freshness: 'fresh', nowSeconds: 100
    });
    note(checks, failures, 'model_running_actions',
      running.title === 'On' && running.primary && running.primary.id === 'turnOff' &&
      running.connection.details.indexOf('Ping is on.') !== -1);

    var unavailable = model.deriveDashboard({
      status: base, hasStatus: true, pair: { state: 'idle' }, freshness: 'unavailable'
    });
    note(checks, failures, 'model_unavailable_truthful',
      unavailable.title === 'Status unavailable' && unavailable.primary && unavailable.primary.id === 'checkNow' &&
      unavailable.connection.value === 'The status is unavailable.');
  }

  function layoutChecks(checks, failures) {
    var shell = document.querySelector('.app-shell');
    var sidebar = document.querySelector('.sidebar');
    var content = element('mainContent');
    var cards = document.querySelectorAll('#view-dashboard .card-grid .card');
    var sidebarRect = sidebar ? sidebar.getBoundingClientRect() : { width: 0 };
    note(checks, failures, 'layout_shell', !!shell && shell.getBoundingClientRect().height > 300);
    note(checks, failures, 'layout_sidebar', sidebarRect.width >= 60, String(Math.round(sidebarRect.width)));
    note(checks, failures, 'layout_content', !!content && content.getBoundingClientRect().width > 320,
      content ? String(Math.round(content.getBoundingClientRect().width)) : 'missing');
    note(checks, failures, 'layout_cards', cards.length === 2, String(cards.length));
    note(checks, failures, 'layout_no_horizontal_overflow',
      document.documentElement.scrollWidth <= window.innerWidth + 1,
      document.documentElement.scrollWidth + ' > ' + window.innerWidth);
    note(checks, failures, 'skip_link_present', !!document.querySelector('.skip-link[href="#mainContent"]'));
  }

  function check() {
    var checks = [];
    var failures = [];

    try {
      note(checks, failures, 'embedded_origin',
        location.protocol === 'tauri:' &&
        location.hostname === 'localhost' &&
        (location.pathname === '' || location.pathname === '/' || location.pathname === '/index.html') &&
        location.search === '',
        location.href);
      note(checks, failures, 'document_title',
        document.title.toLowerCase().indexOf('hotspotshade') !== -1 &&
        document.title.toLowerCase().indexOf('demo') !== -1,
        document.title);
      note(checks, failures, 'shim_installed',
        window.__hotspotshadeBridgeInstalled === true,
        String(window.__hotspotshadeBridgeInstalled));
      note(checks, failures, 'shim_routes_to_demo_api',
        String(window.fetch).indexOf('demo_api') !== -1);
      note(checks, failures, 'menu_bridge_present', typeof window.__hotspotshadeMenu === 'function');

      var pill = element('demoPill');
      note(checks, failures, 'demo_label_present', !!pill);
      if (pill) {
        note(checks, failures, 'demo_label_visible', visible(pill), 'hidden=' + String(pill.hidden));
        note(checks, failures, 'demo_label_text', String(pill.textContent || '').trim() === 'Demo',
          String(pill.textContent || '').trim());
        note(checks, failures, 'demo_label_explains_demo',
          String(pill.title || '').indexOf('Simulated') !== -1,
          String(pill.title || ''));
      }
      var banner = element('demoBanner');
      note(checks, failures, 'demo_banner_visible', visible(banner));
      note(checks, failures, 'demo_banner_explains_demo',
        !!banner && String(banner.textContent || '').indexOf('All data is simulated') !== -1,
        banner ? String(banner.textContent || '').trim() : '');

      note(checks, failures, 'dashboard_ready',
        visible(element('view-dashboard')) &&
        element('sourceValue') && element('sourceValue').textContent !== 'Loading',
        element('sourceValue') ? element('sourceValue').textContent : 'missing');
      note(checks, failures, 'dashboard_unpaired_action',
        visible(element('primaryAction')) &&
        String(element('primaryAction').textContent || '').trim() === 'Pair with source device',
        element('primaryAction') ? element('primaryAction').textContent : 'missing');
      note(checks, failures, 'source_device_not_paired',
        element('sourceValue') && element('sourceValue').textContent === 'Not paired',
        element('sourceValue') ? element('sourceValue').textContent : 'missing');

      layoutChecks(checks, failures);
      modelChecks(checks, failures);

      var external = externalAssets();
      note(checks, failures, 'no_external_assets', external.length === 0, external.join(', '));

      var dashboardNav = document.querySelector('.nav-item[data-view="dashboard"]');
      var activityNav = document.querySelector('.nav-item[data-view="activity"]');
      if (dashboardNav && activityNav) {
        dashboardNav.focus();
        dashboardNav.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
        note(checks, failures, 'nav_arrow_keys', document.activeElement === activityNav,
          document.activeElement ? document.activeElement.className : 'none');
      }

      activityNav.click();
      note(checks, failures, 'activity_view', visible(element('view-activity')));
      note(checks, failures, 'activity_has_demo_entry',
        document.querySelectorAll('#activityList .activity-row').length >= 1,
        String(document.querySelectorAll('#activityList .activity-row').length));
      note(checks, failures, 'activity_details_toggle',
        element('activityDetailsToggle').getAttribute('aria-pressed') === 'false');
      element('activityDetailsToggle').click();
      note(checks, failures, 'activity_details_on',
        element('activityDetailsToggle').getAttribute('aria-pressed') === 'true');
      element('activityDetailsToggle').click();

      var settingsNav = element('settingsNav');
      settingsNav.click();
      note(checks, failures, 'settings_view', visible(element('view-settings')));
      note(checks, failures, 'settings_demo_limits',
        String(element('demoLimits').textContent || '').indexOf('No Windows or Linux tunnel support.') !== -1);
      note(checks, failures, 'settings_ping_toggle',
        !!element('pingToggle') && typeof element('pingToggle').checked === 'boolean');

      element('settingsTabPairing').click();
      note(checks, failures, 'settings_pairing_tab',
        visible(element('settingsPairingPanel')) && !visible(element('settingsGeneralPanel')));
      note(checks, failures, 'settings_pairing_state',
        String(element('settingsPairingState').textContent || '').trim() === 'Not paired',
        element('settingsPairingState').textContent);

      element('settingsTabGeneral').focus();
      element('settingsTabGeneral').dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
      note(checks, failures, 'settings_tab_arrow_keys',
        element('settingsTabPairing').getAttribute('aria-selected') === 'true');

      window.__hotspotshadeMenu('advanced');
      note(checks, failures, 'menu_advanced_view',
        visible(element('view-settings')) && visible(element('settingsAdvancedPanel')) &&
        element('settingsTabAdvanced').getAttribute('aria-selected') === 'true');

      window.__hotspotshadeMenu('dashboard');
      note(checks, failures, 'menu_dashboard_view', visible(element('view-dashboard')));

      var storedThemeBefore = null;
      try {
        storedThemeBefore = localStorage.getItem('hs-theme');
      } catch (error) {
        storedThemeBefore = null;
      }
      var themeBefore = document.documentElement.getAttribute('data-theme');
      var backgroundBefore = getComputedStyle(document.body).backgroundColor;
      window.__hotspotshadeMenu('theme');
      var themeAfter = document.documentElement.getAttribute('data-theme');
      // A slow runner can repaint after the toggle. Wait for the new color.
      var themePromise = waitFor(function () {
        return getComputedStyle(document.body).backgroundColor !== backgroundBefore;
      }, 3000, 'the theme color').then(function () {
        return true;
      }, function () {
        return false;
      }).then(function (changed) {
        note(checks, failures, 'theme_toggle', themeBefore !== themeAfter && changed,
          themeBefore + ' -> ' + themeAfter);
        window.__hotspotshadeMenu('theme');
        try {
          if (storedThemeBefore === null) localStorage.removeItem('hs-theme');
          else localStorage.setItem('hs-theme', storedThemeBefore);
        } catch (error) {
          /* The test must not change the stored preference. */
        }
      });

      themePromise.then(function () {
        return menuChecks(checks, failures);
      }).then(function () {
        return layoutSizes(checks, failures);
      }).then(function () {
        return actionChecks(checks, failures);
      }).then(function () {
        progress('status_fetch');
        return withDeadline(fetch('/api/status', {
          cache: 'no-store',
          headers: { Accept: 'application/json' }
        }), FETCH_DEADLINE_MS);
      }).then(function (response) {
        return response.text().then(function (bodyText) {
          return { status: response.status, cache: response.headers.get('cache-control'), text: bodyText };
        });
      }).then(function (reply) {
        var data = null;
        try {
          data = JSON.parse(reply.text);
        } catch (error) {
          data = null;
        }
        note(checks, failures, 'status_http_200', reply.status === 200, String(reply.status));
        note(checks, failures, 'status_from_shim', reply.cache === 'no-store', String(reply.cache));
        note(checks, failures, 'status_demo_true', !!data && data.demo === true);
        note(checks, failures, 'status_not_running', !!data && data.running === false);
        note(checks, failures, 'status_not_paired_after_forget', !!data && data.paired === false);
        note(checks, failures, 'status_has_no_credential',
          data ? findCredentialKey(data, 'status') === null : false,
          data ? (findCredentialKey(data, 'status') || '') : 'no data');
      }).catch(function (error) {
        note(checks, failures, 'status_fetch', false,
          error && error.message ? error.message : String(error));
      }).then(function () {
        finish(checks, failures);
      });
    } catch (error) {
      note(checks, failures, 'smoke_script', false,
        error && error.message ? error.message : String(error));
      finish(checks, failures);
    }
  }

  function ready() {
    var pill = element('demoPill');
    var source = element('sourceValue');
    return window.__hotspotshadeBridgeInstalled === true &&
      !!pill && pill.hidden === false &&
      !!source && source.textContent !== 'Loading' &&
      typeof window.__hotspotshadeMenu === 'function';
  }

  function waitForPage() {
    if (Date.now() - started > PAGE_DEADLINE_MS) {
      var pill = element('demoPill');
      finish([{
        name: 'page_ready',
        pass: false,
        detail: 'readyState=' + document.readyState +
          ', shim=' + String(window.__hotspotshadeBridgeInstalled) +
          ', demoPill=' + (pill ? 'hidden=' + String(pill.hidden) : 'missing') +
          ', source=' + (element('sourceValue') ? element('sourceValue').textContent : 'missing')
      }], ['The page did not reach the ready state within ' + PAGE_DEADLINE_MS + ' ms.']);
      return;
    }
    if (document.readyState === 'complete' && ready()) {
      setTimeout(check, 0);
      return;
    }
    setTimeout(waitForPage, POLL_MS);
  }

  if (document.readyState === 'complete') {
    setTimeout(waitForPage, 0);
  } else {
    window.addEventListener('load', function () {
      setTimeout(waitForPage, 0);
    });
  }
})();
