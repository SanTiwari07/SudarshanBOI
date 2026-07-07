// src/utils/derive.ts
// All data derivation utilities — compute rich enterprise panel data from the raw API response.

import type { FraudCardData } from '../App';

// ─── Interfaces ────────────────────────────────────────────────────────────────

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: number;
  description: string;
}

export interface PermissionRow {
  name: string;
  shortName: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  reason: string;
  expected: 'Expected' | 'Suspicious' | 'Highly Suspicious' | 'Review';
  fired: boolean;
}

export interface ApiRow {
  api: string;
  purpose: string;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  found: boolean;
}

export interface RiskBreakdownItem {
  label: string;
  score: number;
  maxScore: number;
  color: string;
}

export type IndicatorStatus = 'Detected' | 'Not Detected' | 'Unknown';

export interface ThreatIndicator {
  label: string;
  status: IndicatorStatus;
  description: string;
  icon: string;
}

export interface NetworkEntry {
  host: string;
  fullUrl: string;
  protocol: string;
  reputation: 'Safe' | 'Suspicious' | 'Malicious' | 'Unknown';
  certValid: boolean | null;
  type: 'Domain' | 'IP' | 'Unknown';
}

export interface EvidenceEntry {
  rank: number;
  type: string;
  value: string;
  confidence: number;
  category: 'permission' | 'api' | 'string' | 'url' | 'behavior';
}

export interface AttackChainNode {
  phase: string;
  active: boolean;
  description: string;
}

export interface ChatResponse {
  answer: string;
  evidenceRefs: string[];
}

// ─── Permission Database ────────────────────────────────────────────────────────

const PERM_DB: Record<string, { severity: PermissionRow['severity']; reason: string; expected: PermissionRow['expected'] }> = {
  'BIND_ACCESSIBILITY_SERVICE': { severity: 'Critical', reason: 'Full UI read/write — OTP harvesting, tap injection', expected: 'Highly Suspicious' },
  'READ_SMS': { severity: 'Critical', reason: 'Reads all SMS messages including bank OTPs', expected: 'Highly Suspicious' },
  'RECEIVE_SMS': { severity: 'Critical', reason: 'Intercepts incoming SMS before user sees it', expected: 'Highly Suspicious' },
  'SEND_SMS': { severity: 'High', reason: 'Can silently send premium-rate SMS', expected: 'Suspicious' },
  'SYSTEM_ALERT_WINDOW': { severity: 'High', reason: 'Overlay attack — fake login screen over real apps', expected: 'Suspicious' },
  'REQUEST_INSTALL_PACKAGES': { severity: 'Critical', reason: 'Can silently install other APKs (dropper)', expected: 'Highly Suspicious' },
  'ACCESS_FINE_LOCATION': { severity: 'High', reason: 'Precise GPS tracking without user notice', expected: 'Suspicious' },
  'ACCESS_COARSE_LOCATION': { severity: 'Medium', reason: 'Cell-tower level location tracking', expected: 'Review' },
  'CAMERA': { severity: 'Medium', reason: 'Can capture images/video silently', expected: 'Review' },
  'RECORD_AUDIO': { severity: 'Medium', reason: 'Microphone access for covert audio capture', expected: 'Review' },
  'READ_CONTACTS': { severity: 'Medium', reason: 'Contact list exfiltration vector', expected: 'Review' },
  'WRITE_CONTACTS': { severity: 'High', reason: 'Can modify or delete contact data', expected: 'Suspicious' },
  'READ_CALL_LOG': { severity: 'High', reason: 'Reveals banking and personal call patterns', expected: 'Suspicious' },
  'PROCESS_OUTGOING_CALLS': { severity: 'High', reason: 'Can intercept and redirect calls', expected: 'Suspicious' },
  'READ_EXTERNAL_STORAGE': { severity: 'Low', reason: 'Read access to shared storage', expected: 'Expected' },
  'WRITE_EXTERNAL_STORAGE': { severity: 'Low', reason: 'Write access to shared storage', expected: 'Expected' },
  'INTERNET': { severity: 'Low', reason: 'Standard network access', expected: 'Expected' },
  'RECEIVE_BOOT_COMPLETED': { severity: 'Medium', reason: 'Survives reboot — persistence vector', expected: 'Review' },
  'FOREGROUND_SERVICE': { severity: 'Low', reason: 'Background service indicator', expected: 'Expected' },
  'WAKE_LOCK': { severity: 'Low', reason: 'Prevents device sleep for background ops', expected: 'Expected' },
  'VIBRATE': { severity: 'Low', reason: 'Haptic feedback', expected: 'Expected' },
  'BLUETOOTH': { severity: 'Medium', reason: 'Nearby device discovery/communication', expected: 'Review' },
  'BLUETOOTH_ADMIN': { severity: 'Medium', reason: 'Manages Bluetooth connections', expected: 'Review' },
  'BLUETOOTH_CONNECT': { severity: 'Medium', reason: 'BLE pairing without user prompt', expected: 'Review' },
  'NFC': { severity: 'Medium', reason: 'Near-field communication — relay attacks', expected: 'Review' },
  'ACCESS_NETWORK_STATE': { severity: 'Low', reason: 'Reads connectivity status', expected: 'Expected' },
  'ACCESS_WIFI_STATE': { severity: 'Low', reason: 'Reads WiFi SSID/BSSID', expected: 'Expected' },
  'CHANGE_NETWORK_STATE': { severity: 'Medium', reason: 'Can disconnect device from network', expected: 'Review' },
  'KILL_BACKGROUND_PROCESSES': { severity: 'Medium', reason: 'Can terminate AV/security apps', expected: 'Review' },
  'GET_TASKS': { severity: 'Medium', reason: 'Detects foreground app (banking app detection)', expected: 'Suspicious' },
  'USE_BIOMETRIC': { severity: 'Medium', reason: 'Biometric bypass attempt surface', expected: 'Review' },
  'USE_FINGERPRINT': { severity: 'Medium', reason: 'Legacy fingerprint API access', expected: 'Review' },
};

// ─── API Database ───────────────────────────────────────────────────────────────

const API_DB: Record<string, { purpose: string; risk: ApiRow['risk'] }> = {
  'addJavascriptInterface': { purpose: 'Injects Java bridge into WebView — JavaScript-to-native RCE', risk: 'Critical' },
  'Runtime.exec': { purpose: 'Shell command execution on device OS', risk: 'Critical' },
  'ProcessBuilder.start': { purpose: 'Spawns OS child processes for command execution', risk: 'High' },
  'DexClassLoader': { purpose: 'Loads compiled DEX code from arbitrary paths at runtime', risk: 'Critical' },
  'PathClassLoader': { purpose: 'Dynamic class loading from device filesystem paths', risk: 'High' },
  'System.loadLibrary': { purpose: 'Loads native (.so) shared library at runtime', risk: 'High' },
};

const ALL_TRACKED_APIS = Object.keys(API_DB);

// ─── MITRE ATT&CK Database ──────────────────────────────────────────────────────

const MITRE_DB: Record<string, Omit<MitreTechnique, 'id' | 'confidence'>> = {
  'T1411': { name: 'Input Capture via Accessibility', tactic: 'Collection', severity: 'Critical', description: 'Abuses AccessibilityService to silently capture keystrokes and UI content including bank OTPs.' },
  'T1412': { name: 'Capture SMS Messages', tactic: 'Collection', severity: 'Critical', description: 'Uses READ_SMS/RECEIVE_SMS permissions to intercept one-time passwords and 2FA codes.' },
  'T1437': { name: 'Standard Application Layer Protocol', tactic: 'Command & Control', severity: 'High', description: 'Uses standard HTTP/HTTPS to blend C2 traffic with legitimate web requests.' },
  'T1407': { name: 'Download New Code at Runtime', tactic: 'Defense Evasion', severity: 'Critical', description: 'Dynamically loads DEX payloads post-installation, bypassing static analysis at upload time.' },
  'T1444': { name: 'Masquerade as Legitimate Application', tactic: 'Defense Evasion', severity: 'High', description: 'Overlay via SYSTEM_ALERT_WINDOW to display fake banking login screens over real apps.' },
  'T1516': { name: 'Input Injection via WebView', tactic: 'Impact', severity: 'Critical', description: 'addJavascriptInterface exposes native methods to attacker-controlled JavaScript code.' },
  'T1603': { name: 'Scheduled Task / Shell Execution', tactic: 'Execution', severity: 'High', description: 'Runtime.exec / ProcessBuilder used to execute attacker-controlled shell commands.' },
  'T1430': { name: 'Location Tracking', tactic: 'Collection', severity: 'High', description: 'Collects precise GPS coordinates via ACCESS_FINE_LOCATION without a clear user-facing need.' },
  'T1421': { name: 'System Network Configuration Discovery', tactic: 'Discovery', severity: 'Medium', description: 'Queries device network configuration to profile victim infrastructure.' },
  'T1418': { name: 'Application Discovery (Banking Targets)', tactic: 'Discovery', severity: 'High', description: 'Scans for installed banking apps by package name to trigger targeted overlay attacks.' },
  'T1406': { name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', severity: 'Medium', description: 'Uses dynamic class loading to hide malicious logic from static scanners.' },
};

// ─── Derivation Functions ───────────────────────────────────────────────────────

export function getMitreAttack(data: FraudCardData): MitreTechnique[] {
  const techniques: Array<{ id: string; confidence: number }> = [];

  if (data.has_accessibility_abuse) {
    techniques.push({ id: 'T1411', confidence: 92 });
  }
  if (data.has_sms_read_write) {
    techniques.push({ id: 'T1412', confidence: 95 });
  }
  if (data.has_system_alert_window) {
    techniques.push({ id: 'T1444', confidence: 87 });
  }
  if (data.hardcoded_urls_ips.length > 0) {
    techniques.push({ id: 'T1437', confidence: 78 });
  }
  if (data.technical_view.apis_fired.includes('DexClassLoader') || data.technical_view.apis_fired.includes('PathClassLoader')) {
    techniques.push({ id: 'T1407', confidence: 89 });
    techniques.push({ id: 'T1406', confidence: 75 });
  }
  if (data.technical_view.apis_fired.includes('addJavascriptInterface')) {
    techniques.push({ id: 'T1516', confidence: 91 });
  }
  if (data.technical_view.apis_fired.some(a => ['Runtime.exec', 'ProcessBuilder.start'].includes(a))) {
    techniques.push({ id: 'T1603', confidence: 84 });
  }
  if (data.targets_indian_banks) {
    techniques.push({ id: 'T1418', confidence: 93 });
  }
  if (data.all_permissions.some(p => p.includes('ACCESS_FINE_LOCATION'))) {
    techniques.push({ id: 'T1430', confidence: 80 });
  }

  // Always include network discovery if any URLs found
  if (data.hardcoded_urls_ips.length > 0 || data.targets_indian_banks) {
    techniques.push({ id: 'T1421', confidence: 60 });
  }

  // Deduplicate
  const seen = new Set<string>();
  const unique = techniques.filter(t => {
    if (seen.has(t.id)) return false;
    seen.add(t.id);
    return true;
  });

  return unique
    .map(t => ({ id: t.id, confidence: t.confidence, ...MITRE_DB[t.id] }))
    .filter(t => t.name)
    .sort((a, b) => b.confidence - a.confidence);
}

export function getPermissionTable(data: FraudCardData): PermissionRow[] {
  const firedSet = new Set(data.technical_view.permissions_fired);
  const permissions = data.all_permissions.length > 0
    ? data.all_permissions
    : data.technical_view.permissions_fired;

  const rows: PermissionRow[] = permissions.slice(0, 20).map(fullPerm => {
    const short = fullPerm.split('.').pop() || fullPerm;
    const db = PERM_DB[short] || { severity: 'Low' as const, reason: 'Standard permission', expected: 'Expected' as const };
    return {
      name: fullPerm,
      shortName: short.replace(/_/g, ' '),
      severity: db.severity,
      reason: db.reason,
      expected: db.expected,
      fired: firedSet.has(fullPerm),
    };
  });

  return rows.sort((a, b) => {
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    return order[a.severity] - order[b.severity];
  });
}

export function getApiTable(data: FraudCardData): ApiRow[] {
  const foundSet = new Set(data.technical_view.apis_fired);
  return ALL_TRACKED_APIS.map(api => ({
    api,
    purpose: API_DB[api].purpose,
    risk: API_DB[api].risk,
    found: foundSet.has(api),
  })).sort((a, b) => {
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    return order[a.risk] - order[b.risk];
  });
}

export function getRiskBreakdown(data: FraudCardData): RiskBreakdownItem[] {
  // Reproduce the risk_engine.py formula on the frontend
  const permRisk = (data.has_accessibility_abuse ? 1.5 : 0) +
                   (data.has_sms_read_write ? 1.0 : 0) +
                   (data.has_system_alert_window ? 1.0 : 0);

  const nonObfApis = data.technical_view.apis_fired.filter(a =>
    !['DexClassLoader', 'PathClassLoader', 'System.loadLibrary'].includes(a));
  const obfApis = data.technical_view.apis_fired.filter(a =>
    ['DexClassLoader', 'PathClassLoader'].includes(a));
  const nativeApis = data.technical_view.apis_fired.filter(a => a === 'System.loadLibrary');

  const networkRisk = (data.targets_indian_banks ? 1.0 : 0) + Math.min(data.hardcoded_urls_ips.length * 0.3, 3.0);

  const permScore = parseFloat((25 * permRisk).toFixed(1));
  const netScore = parseFloat((10 * networkRisk).toFixed(1));

  // Obfuscation + native libs are subsets of apiScore
  const obfScore = parseFloat((obfApis.length * 7.5).toFixed(1));
  const nativeScore = parseFloat((nativeApis.length * 5).toFixed(1));
  const pureApiScore = Math.max(0, parseFloat((nonObfApis.length * 7.5).toFixed(1)));

  const stringScore = Math.min(
    data.technical_view.strings_fired.filter(s => !s.startsWith('http')).length * 2,
    10
  );

  return [
    { label: 'Permissions', score: permScore, maxScore: 87.5, color: 'bg-red-500' },
    { label: 'Dangerous APIs', score: pureApiScore, maxScore: 30, color: 'bg-orange-500' },
    { label: 'Network Indicators', score: netScore, maxScore: 40, color: 'bg-yellow-500' },
    { label: 'Obfuscation / Reflection', score: obfScore, maxScore: 30, color: 'bg-purple-500' },
    { label: 'Native Libraries', score: nativeScore, maxScore: 10, color: 'bg-blue-500' },
    { label: 'Sensitive Strings', score: stringScore, maxScore: 10, color: 'bg-gray-500' },
  ];
}

export function getThreatIndicators(data: FraudCardData): ThreatIndicator[] {
  const hasApi = (name: string) => data.technical_view.apis_fired.includes(name);

  return [
    {
      label: 'Accessibility Abuse',
      status: data.has_accessibility_abuse ? 'Detected' : 'Not Detected',
      description: 'BIND_ACCESSIBILITY_SERVICE — can read screen content and inject taps',
      icon: '👁',
    },
    {
      label: 'SMS Interception',
      status: data.has_sms_read_write ? 'Detected' : 'Not Detected',
      description: 'READ/RECEIVE_SMS — captures OTPs and 2FA codes',
      icon: '📱',
    },
    {
      label: 'Overlay Attack',
      status: data.has_system_alert_window ? 'Detected' : 'Not Detected',
      description: 'SYSTEM_ALERT_WINDOW — draws fake login screens over banking apps',
      icon: '🪟',
    },
    {
      label: 'Dynamic Code Loading',
      status: (hasApi('DexClassLoader') || hasApi('PathClassLoader')) ? 'Detected' : 'Not Detected',
      description: 'Loads new DEX payloads after install — evades static analysis',
      icon: '⚙️',
    },
    {
      label: 'Native Library Loading',
      status: hasApi('System.loadLibrary') ? 'Detected' : 'Not Detected',
      description: 'Loads native .so libraries that bypass Java-layer analysis',
      icon: '📦',
    },
    {
      label: 'WebView Injection',
      status: hasApi('addJavascriptInterface') ? 'Detected' : 'Not Detected',
      description: 'addJavascriptInterface exposes native methods to JavaScript',
      icon: '🌐',
    },
    {
      label: 'Shell Execution',
      status: (hasApi('Runtime.exec') || hasApi('ProcessBuilder.start')) ? 'Detected' : 'Not Detected',
      description: 'Executes OS shell commands — privilege escalation vector',
      icon: '💻',
    },
    {
      label: 'Banking App Targeting',
      status: data.targets_indian_banks ? 'Detected' : 'Not Detected',
      description: 'Contains Indian bank package names — targeted overlay campaign',
      icon: '🏦',
    },
    {
      label: 'Hardcoded Network IOCs',
      status: data.hardcoded_urls_ips.length > 0 ? 'Detected' : 'Not Detected',
      description: `${data.hardcoded_urls_ips.length} hardcoded URLs/IPs found in DEX strings`,
      icon: '🔗',
    },
    {
      label: 'Anti-Analysis / Root Detection',
      status: 'Unknown',
      description: 'Dynamic sandbox required to confirm root detection routines',
      icon: '🔍',
    },
  ];
}

export function getNetworkIntel(data: FraudCardData): NetworkEntry[] {
  const SAFE_DOMAINS = ['adobe.com', 'google.com', 'android.com', 'googleapis.com', 'gstatic.com',
                        'schema.org', 'w3.org', 'xmlpull.org', 'apache.org', 'microsoft.com'];
  const SUSP_PATTERNS = ['pastebin', 'ngrok', '.xyz', '.tk', '.top', '.pw', '.cc'];
  const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

  return data.hardcoded_urls_ips.slice(0, 15).map(rawUrl => {
    let host = rawUrl;
    let protocol = 'Unknown';
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
      host = parsed.hostname;
      protocol = parsed.protocol.replace(':', '').toUpperCase();
    } catch {
      host = rawUrl;
    }

    const isIP = IP_RE.test(host);
    const isSafe = SAFE_DOMAINS.some(d => host.endsWith(d));
    const isSusp = SUSP_PATTERNS.some(p => host.includes(p)) || isIP;
    const reputation: NetworkEntry['reputation'] = isSusp ? 'Suspicious' : isSafe ? 'Safe' : 'Unknown';

    return {
      host,
      fullUrl: rawUrl,
      protocol: protocol || 'HTTP',
      reputation,
      certValid: protocol === 'HTTPS' ? true : protocol === 'HTTP' ? false : null,
      type: isIP ? 'IP' : 'Domain',
    };
  });
}

export function getTopEvidence(data: FraudCardData): EvidenceEntry[] {
  const entries: EvidenceEntry[] = [];

  // High-value permissions
  if (data.has_accessibility_abuse) entries.push({ rank: 0, type: 'Permission', value: 'BIND_ACCESSIBILITY_SERVICE', confidence: 97, category: 'permission' });
  if (data.has_sms_read_write) entries.push({ rank: 0, type: 'Permission', value: 'READ_SMS / RECEIVE_SMS', confidence: 95, category: 'permission' });
  if (data.has_system_alert_window) entries.push({ rank: 0, type: 'Permission', value: 'SYSTEM_ALERT_WINDOW', confidence: 91, category: 'permission' });

  // Dangerous APIs
  data.technical_view.apis_fired.forEach(api => {
    const db = API_DB[api];
    if (db) {
      const confMap: Record<string, number> = { Critical: 93, High: 85, Medium: 72, Low: 55 };
      entries.push({ rank: 0, type: 'Dangerous API', value: api, confidence: confMap[db.risk] || 70, category: 'api' });
    }
  });

  // Hardcoded URLs/IPs
  data.hardcoded_urls_ips.slice(0, 3).forEach(url => {
    const isSusp = ['pastebin', 'ngrok', '.xyz'].some(p => url.includes(p));
    entries.push({ rank: 0, type: 'Hardcoded URL', value: url, confidence: isSusp ? 88 : 65, category: 'url' });
  });

  // Banking targeting
  if (data.targets_indian_banks) {
    entries.push({ rank: 0, type: 'Banking Target', value: 'Indian Bank Package Names Detected', confidence: 90, category: 'behavior' });
  }

  // Suspicious strings
  data.technical_view.strings_fired
    .filter(s => !s.startsWith('http'))
    .slice(0, 2)
    .forEach(s => entries.push({ rank: 0, type: 'Suspicious String', value: s.slice(0, 60), confidence: 60, category: 'string' }));

  return entries
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 8)
    .map((e, i) => ({ ...e, rank: i + 1 }));
}

export function getAttackChain(data: FraudCardData): AttackChainNode[] {
  return [
    {
      phase: 'APK Installed',
      active: true,
      description: 'Application sideloaded or installed from unofficial source',
    },
    {
      phase: 'Permissions Granted',
      active: data.has_accessibility_abuse || data.has_sms_read_write || data.has_system_alert_window,
      description: data.technical_view.permissions_fired.length > 0
        ? `${data.technical_view.permissions_fired.length} critical permission(s) accepted by user`
        : 'No critical permissions granted',
    },
    {
      phase: 'Sensitive APIs Activated',
      active: data.technical_view.apis_fired.length > 0,
      description: data.technical_view.apis_fired.length > 0
        ? `${data.technical_view.apis_fired.join(', ')} APIs in use`
        : 'No dangerous API usage detected',
    },
    {
      phase: 'Network Communication',
      active: data.hardcoded_urls_ips.length > 0,
      description: data.hardcoded_urls_ips.length > 0
        ? `${data.hardcoded_urls_ips.length} hardcoded endpoint(s) — potential C2 beaconing`
        : 'No suspicious network indicators',
    },
    {
      phase: 'Data Collection',
      active: data.has_accessibility_abuse || data.has_sms_read_write,
      description: data.has_sms_read_write
        ? 'OTP/SMS interception possible if SMS permissions active'
        : data.has_accessibility_abuse
        ? 'Screen content readable via Accessibility'
        : 'No active data collection detected',
    },
    {
      phase: 'Potential Exfiltration',
      active: (data.has_accessibility_abuse || data.has_sms_read_write) && data.hardcoded_urls_ips.length > 0,
      description: 'Combined: screen data + C2 endpoints = exfiltration risk',
    },
  ];
}

export function getConfidencePercent(data: FraudCardData): number {
  // Confidence = base confidence from ai_multiplier scaled + flag certainty bonus
  const base = Math.round(data.ai_confidence_multiplier * 70 + 20);
  const flagBonus = [
    data.has_accessibility_abuse,
    data.has_sms_read_write,
    data.has_system_alert_window,
    data.technical_view.apis_fired.length > 0,
    data.hardcoded_urls_ips.length > 0,
  ].filter(Boolean).length * 2;
  return Math.min(base + flagBonus, 99);
}

export function generateAIResponse(question: string, data: FraudCardData): ChatResponse {
  const q = question.toLowerCase();
  const score = data.final_risk_score.toFixed(1);
  const band = data.risk_band;

  if (q.includes('safe') || q.includes('why safe') || q.includes('classify')) {
    if (['Safe', 'safe'].includes(data.risk_band)) {
      const reasons = ['deterministic static analysis found no critical behavioral clusters'];
      if (!data.has_accessibility_abuse) reasons.push('no Accessibility abuse');
      if (!data.has_sms_read_write) reasons.push('no SMS interception');
      if (!data.has_system_alert_window) reasons.push('no overlay capability');
      return {
        answer: `This APK scored ${score}/100 (${band}) because ${reasons.join(', ')}. The matched rule was: "${data.technical_view.matched_rule}". While ${data.hardcoded_urls_ips.length > 0 ? `${data.hardcoded_urls_ips.length} URL(s) were found in DEX strings` : 'no URLs were flagged'}, these alone are insufficient to trigger a malicious classification without supporting behavioral flags.`,
        evidenceRefs: data.hardcoded_urls_ips.slice(0, 2),
      };
    }
    return {
      answer: `This APK is NOT safe — it scored ${score}/100 (${band}). Key reasons: ${[data.has_accessibility_abuse && 'Accessibility abuse', data.has_sms_read_write && 'SMS interception', data.has_system_alert_window && 'overlay capability'].filter(Boolean).join(', ')}.`,
      evidenceRefs: data.technical_view.permissions_fired.slice(0, 2),
    };
  }

  if (q.includes('score') || q.includes('increas') || q.includes('contribut')) {
    const reasons: string[] = [];
    if (data.has_accessibility_abuse) reasons.push('BIND_ACCESSIBILITY_SERVICE (+37.5 pts on permission axis)');
    if (data.has_sms_read_write) reasons.push('READ/RECEIVE_SMS (+25 pts on permission axis)');
    if (data.has_system_alert_window) reasons.push('SYSTEM_ALERT_WINDOW (+25 pts on permission axis)');
    data.technical_view.apis_fired.forEach(a => reasons.push(`${a} API (+${API_DB[a]?.risk === 'Critical' ? 7.5 : 5} pts on API axis)`));
    if (data.hardcoded_urls_ips.length > 0) reasons.push(`${data.hardcoded_urls_ips.length} hardcoded URLs (+${(data.hardcoded_urls_ips.length * 3).toFixed(0)} pts on network axis)`);
    if (reasons.length === 0) return { answer: `The score of ${score}/100 is low because no significant threat indicators were found. Only minor evidence like ${data.technical_view.strings_fired.length} suspicious strings were detected.`, evidenceRefs: [] };
    return {
      answer: `Risk score drivers (${score}/100): ${reasons.join('; ')}. AI confidence multiplier: ×${data.ai_confidence_multiplier.toFixed(2)}.`,
      evidenceRefs: reasons.slice(0, 2),
    };
  }

  if (q.includes('bluetooth') || q.includes('network') || q.includes('url') || q.includes('domain')) {
    const urls = data.hardcoded_urls_ips;
    if (urls.length === 0) return { answer: 'No hardcoded URLs or IP addresses were found in the DEX bytecode. Network communication cannot be confirmed through static analysis alone — dynamic sandbox analysis is recommended.', evidenceRefs: [] };
    return {
      answer: `${urls.length} hardcoded network indicator(s) found in DEX strings: ${urls.slice(0, 3).join(', ')}${urls.length > 3 ? ` and ${urls.length - 3} more` : ''}. ${urls.some(u => ['pastebin', 'ngrok'].some(p => u.includes(p))) ? 'Pastebin/ngrok usage detected — commonly used for C2 infrastructure staging.' : 'Domains appear non-malicious based on static reputation, but confirm with dynamic analysis.'}`,
      evidenceRefs: urls.slice(0, 3),
    };
  }

  if (q.includes('block') || q.includes('deploy') || q.includes('action') || q.includes('recommend')) {
    if (data.final_risk_score <= 30) return { answer: `Score: ${score}/100 (${band}). Recommendation: Safe to deploy under standard monitoring. No critical indicators found. Review any future app updates as risk profiles can change with new versions.`, evidenceRefs: [] };
    if (data.final_risk_score <= 60) return { answer: `Score: ${score}/100 (${band}). Recommendation: Do NOT deploy without additional review. Isolate the device, audit all flagged permissions, and run dynamic sandbox analysis before clearance.`, evidenceRefs: data.technical_view.permissions_fired };
    return { answer: `Score: ${score}/100 (${band}). Recommendation: BLOCK immediately. This APK exhibits clear malware behavioral patterns. Isolate affected devices, revoke app permissions, and escalate to IR team.`, evidenceRefs: [...data.technical_view.permissions_fired, ...data.technical_view.apis_fired] };
  }

  if (q.includes('evidence') || q.includes('support') || q.includes('proof')) {
    const ev = getTopEvidence(data);
    if (ev.length === 0) return { answer: 'No significant evidence was found. The APK appears benign based on static analysis.', evidenceRefs: [] };
    return {
      answer: `Top ${ev.length} evidence items supporting the ${band} classification: ${ev.map(e => `${e.type}: ${e.value} (${e.confidence}% confidence)`).join('; ')}.`,
      evidenceRefs: ev.map(e => e.value).slice(0, 4),
    };
  }

  if (q.includes('mitre') || q.includes('att&ck') || q.includes('technique')) {
    const techs = getMitreAttack(data);
    if (techs.length === 0) return { answer: 'No MITRE ATT&CK for Mobile techniques could be mapped based on the current evidence. The APK shows insufficient behavioral indicators for technique attribution.', evidenceRefs: [] };
    return {
      answer: `${techs.length} MITRE ATT&CK for Mobile techniques mapped: ${techs.map(t => `${t.id} ${t.name} (${t.confidence}% confidence, tactic: ${t.tactic})`).join('; ')}.`,
      evidenceRefs: techs.map(t => t.id),
    };
  }

  // Fallback
  return {
    answer: `Analysis complete for ${data.package_name || 'this APK'}. Risk score: ${score}/100 (${band}). Family classification: ${data.family_classification}. ${data.technical_view.apis_fired.length} dangerous API(s), ${data.technical_view.permissions_fired.length} critical permission(s), ${data.hardcoded_urls_ips.length} network indicator(s) found. Ask me about specific topics like score breakdown, MITRE techniques, network intelligence, or recommended actions.`,
    evidenceRefs: [],
  };
}

// ─── Severity Color Helpers ─────────────────────────────────────────────────────

export function severityBg(s: string): string {
  switch (s.toLowerCase()) {
    case 'critical': return 'bg-red-100 text-red-800 border border-red-200';
    case 'high':     return 'bg-orange-100 text-orange-800 border border-orange-200';
    case 'medium':   return 'bg-yellow-100 text-yellow-800 border border-yellow-200';
    default:         return 'bg-green-100 text-green-800 border border-green-200';
  }
}

export function riskBandBg(band: string): string {
  switch (band.toLowerCase()) {
    case 'critical':  return 'bg-red-600 text-white';
    case 'high risk': return 'bg-orange-500 text-white';
    case 'suspicious': return 'bg-yellow-400 text-gray-900';
    default:           return 'bg-green-500 text-white';
  }
}

export function riskBandText(band: string): string {
  switch (band.toLowerCase()) {
    case 'critical':  return 'text-red-600';
    case 'high risk': return 'text-orange-500';
    case 'suspicious': return 'text-yellow-600';
    default:           return 'text-green-600';
  }
}

export function statusChip(status: IndicatorStatus): string {
  switch (status) {
    case 'Detected':     return 'bg-red-100 text-red-700 border border-red-200';
    case 'Not Detected': return 'bg-green-100 text-green-700 border border-green-200';
    default:             return 'bg-gray-100 text-gray-600 border border-gray-200';
  }
}

export function expectedChip(expected: PermissionRow['expected']): string {
  switch (expected) {
    case 'Highly Suspicious': return 'bg-red-100 text-red-700 border border-red-200';
    case 'Suspicious':        return 'bg-orange-100 text-orange-700 border border-orange-200';
    case 'Review':            return 'bg-yellow-100 text-yellow-700 border border-yellow-200';
    default:                  return 'bg-green-100 text-green-700 border border-green-200';
  }
}

// ─── Export Helpers ─────────────────────────────────────────────────────────────

export function exportJSON(data: FraudCardData): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sudarshan-report-${data.sha256.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportCSV(data: FraudCardData): void {
  const iocs = [
    ...data.hardcoded_urls_ips.map(u => ({ type: 'URL', value: u })),
    ...data.technical_view.permissions_fired.map(p => ({ type: 'Permission', value: p })),
    ...data.technical_view.apis_fired.map(a => ({ type: 'API', value: a })),
    { type: 'SHA256', value: data.sha256 },
  ];
  const csv = ['Type,Value', ...iocs.map(i => `${i.type},"${i.value}"`)].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `sudarshan-ioc-${data.sha256.slice(0, 8)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
