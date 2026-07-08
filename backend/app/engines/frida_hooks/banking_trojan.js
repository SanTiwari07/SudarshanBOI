/**
 * SUDARSHAN — Banking Trojan Frida Instrumentation Script
 * =========================================================
 * Hooks critical Android APIs used by banking malware.
 * Reports behavioral events to the Python controller via Frida's send() API.
 *
 * Detected behaviors:
 *   [A] Accessibility Service abuse       → weight 0.35
 *   [S] SMS interception / OTP theft      → weight 0.25
 *   [O] Overlay / System Alert Window     → weight 0.20
 *   [B] Banking app interaction           → weight 0.10
 *   [N] Network C2 communication         → weight 0.05
 *   [P] Persistence / Admin abuse         → weight 0.05
 *
 * These weights implement the BFCI formula from the Sudarshan proposal.
 */

'use strict';

// ─── Event Collector ─────────────────────────────────────────────────────────

var events = {
  accessibility: [],
  sms: [],
  overlay: [],
  banking: [],
  network: [],
  persistence: [],
  dangerous_apis: [],
  files_accessed: [],
};

function emit(category, data) {
  var event = {
    timestamp: Date.now(),
    category: category,
    data: data,
  };
  if (events[category]) {
    events[category].push(event);
  }
  send({ type: 'event', payload: event });
}

// ─── [A] Accessibility Service Hooks ─────────────────────────────────────────

function waitForJava() {
  if (typeof Java !== 'undefined' && Java.available) {
    initHooks();
  } else {
    setTimeout(waitForJava, 100);
  }
}

setImmediate(waitForJava);

function initHooks() {
  try {
    Java.perform(function () {

try {
  var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');

  AccessibilityService.onAccessibilityEvent.implementation = function (event) {
    var eventType = event.getEventType();
    var pkgName = event.getPackageName();
    emit('accessibility', {
      hook: 'AccessibilityService.onAccessibilityEvent',
      event_type: eventType,
      package: pkgName ? pkgName.toString() : null,
      description: 'App is monitoring screen content via Accessibility API',
    });
    return this.onAccessibilityEvent(event);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'AccessibilityService.onAccessibilityEvent', error: e.message });
}

try {
  var AccessibilityNodeInfo = Java.use('android.view.accessibility.AccessibilityNodeInfo');

  AccessibilityNodeInfo.getText.implementation = function () {
    var text = this.getText();
    if (text) {
      emit('accessibility', {
        hook: 'AccessibilityNodeInfo.getText',
        text_length: text.length(),
        description: 'App is extracting text from UI elements via Accessibility (credential/OTP theft)',
      });
    }
    return text;
  };

  AccessibilityNodeInfo.performAction.implementation = function (action) {
    emit('accessibility', {
      hook: 'AccessibilityNodeInfo.performAction',
      action: action,
      description: 'App is performing automated UI action (gesture replay / ATS transaction manipulation)',
    });
    return this.performAction(action);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'AccessibilityNodeInfo', error: e.message });
}

// ─── [S] SMS / OTP Interception Hooks ────────────────────────────────────────

try {
  var SmsMessage = Java.use('android.telephony.SmsMessage');

  SmsMessage.getMessageBody.implementation = function () {
    var body = this.getMessageBody();
    emit('sms', {
      hook: 'SmsMessage.getMessageBody',
      body_length: body ? body.length() : 0,
      description: 'App is reading incoming SMS message body (OTP interception)',
    });
    return body;
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'SmsMessage.getMessageBody', error: e.message });
}

try {
  var SmsManager = Java.use('android.telephony.SmsManager');

  SmsManager.sendTextMessage.implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
    emit('sms', {
      hook: 'SmsManager.sendTextMessage',
      destination: destinationAddress,
      text_length: text ? text.length() : 0,
      description: 'App is sending an SMS (potential fraud forwarding)',
    });
    return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'SmsManager.sendTextMessage', error: e.message });
}

// ─── [O] Overlay / System Alert Window Hooks ─────────────────────────────────

try {
  var WindowManager = Java.use('android.view.WindowManager');
  var LayoutParams = Java.use('android.view.WindowManager$LayoutParams');

  // Hook addView to detect overlay creation
  var wm_impl = Java.use('android.view.WindowManagerImpl');
  wm_impl.addView.overload('android.view.View', 'android.view.ViewGroup$LayoutParams').implementation = function (view, params) {
    if (params instanceof LayoutParams.$jni_type) {
      var lp = Java.cast(params, LayoutParams);
      var type = lp.type.value;
      // TYPE_APPLICATION_OVERLAY = 2038, TYPE_SYSTEM_ALERT = 2003
      if (type === 2038 || type === 2003 || type === 2010) {
        emit('overlay', {
          hook: 'WindowManager.addView',
          window_type: type,
          description: 'App is drawing an overlay window on top of other apps (phishing screen / credential capture)',
        });
      }
    }
    return this.addView(view, params);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'WindowManager.addView', error: e.message });
}

// ─── [B] Banking App Interaction Hooks ───────────────────────────────────────

var BANKING_PACKAGES = [
  'com.boi.mobile', 'com.sbi.lotusintouch', 'com.snapwork.hdfc',
  'com.icici.mobile', 'com.axis.mobile', 'in.org.npci.upiapp',
  'net.one97.paytm', 'com.phonepe.app', 'com.google.android.apps.nbu.paisa.user',
  'com.amazon.mShop.android.shopping', 'com.whatsapp',
];

try {
  var ActivityManager = Java.use('android.app.ActivityManager');

  ActivityManager.getRunningTasks.implementation = function (maxNum) {
    var tasks = this.getRunningTasks(maxNum);
    if (tasks && tasks.size() > 0) {
      var topTask = tasks.get(0);
      var topActivity = topTask.topActivity;
      if (topActivity) {
        var pkg = topActivity.getPackageName();
        if (BANKING_PACKAGES.indexOf(pkg) !== -1) {
          emit('banking', {
            hook: 'ActivityManager.getRunningTasks',
            target_package: pkg,
            description: 'Malware is monitoring foreground banking app (pre-overlay positioning)',
          });
        }
      }
    }
    return tasks;
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'ActivityManager.getRunningTasks', error: e.message });
}

// ─── [N] Network C2 Communication Hooks ──────────────────────────────────────

try {
  var URL = Java.use('java.net.URL');

  URL.openConnection.overload().implementation = function () {
    var urlStr = this.toString();
    emit('network', {
      hook: 'URL.openConnection',
      url: urlStr,
      description: 'App is making a network connection (potential C2 communication)',
    });
    return this.openConnection();
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'URL.openConnection', error: e.message });
}

try {
  var OkHttpClient = null;
  try { OkHttpClient = Java.use('okhttp3.OkHttpClient'); } catch (e2) {}

  if (OkHttpClient) {
    var RealCall = Java.use('okhttp3.internal.connection.RealCall');
    RealCall.execute.implementation = function () {
      var request = this.request();
      emit('network', {
        hook: 'OkHttp.RealCall.execute',
        url: request.url().toString(),
        method: request.method(),
        description: 'OkHttp request executed (C2 data exfiltration)',
      });
      return this.execute();
    };
  }
} catch (e) {
  send({ type: 'hook_error', hook: 'OkHttp', error: e.message });
}

// ─── [P] Persistence / Admin Abuse Hooks ─────────────────────────────────────

try {
  var DevicePolicyManager = Java.use('android.app.admin.DevicePolicyManager');

  DevicePolicyManager.isAdminActive.implementation = function (who) {
    emit('persistence', {
      hook: 'DevicePolicyManager.isAdminActive',
      description: 'App is checking Device Admin status (persistence mechanism)',
    });
    return this.isAdminActive(who);
  };

  DevicePolicyManager.lockNow.implementation = function () {
    emit('persistence', {
      hook: 'DevicePolicyManager.lockNow',
      description: 'App is LOCKING THE DEVICE (ransomware or extortion behavior)',
    });
    return this.lockNow();
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'DevicePolicyManager', error: e.message });
}

// ─── [D] Dynamic Code Loading Hooks ──────────────────────────────────────────

try {
  var DexClassLoader = Java.use('dalvik.system.DexClassLoader');

  DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
    emit('dangerous_apis', {
      hook: 'DexClassLoader.<init>',
      dex_path: dexPath,
      description: 'App is dynamically loading a DEX file (malicious payload dropper)',
    });
    return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'DexClassLoader', error: e.message });
}

// ─── File Access Hooks ────────────────────────────────────────────────────────

try {
  var File = Java.use('java.io.File');

  File.$init.overload('java.lang.String').implementation = function (path) {
    var p = path.toString();
    if (p.indexOf('/data/data') !== -1 || p.indexOf('shared_prefs') !== -1) {
      emit('files_accessed', {
        hook: 'File.<init>',
        path: p,
        description: 'App is accessing sensitive app data directory',
      });
    }
    return this.$init(path);
  };
} catch (e) {
  send({ type: 'hook_error', hook: 'File', error: e.message });
}

// ─── Heartbeat ────────────────────────────────────────────────────────────────

    }); // end Java.perform
    
    send({ type: 'ready', message: 'SUDARSHAN Frida hooks loaded — monitoring banking trojan behavior' });
  } catch (e) {
    send({ type: 'error', description: 'Exception during hook initialization: ' + e.message });
  }
} // end initHooks
