// Security posture: a set of checks over the config snapshot, threat history and firewall
// analysis, each producing an explained finding (and a fix when one can be automated).

import type {
  ExposureItem, Finding, FindingCategory, HygieneIssue, Posture, RiskAcceptance, SegmentationMatrix, Severity, TemplateCategory, TemplateStatus, ThreatSummary,
} from '../../shared/types.ts';
import type { RawSnapshot } from '../unifi/collect.ts';
import type { FwModel } from './model.ts';
import { isUntrusted, label as roleLabel } from './roles.ts';
import { RISKY_EXPOSED_PORTS, portName, sevRank } from './threatKb.ts';
import { AddrSet, parsePorts } from './sets.ts';
import { reachableGatewayMgmt } from './segmentation.ts';
import { TEMPLATES } from './hardening/templates.ts';
import { groupCounts, ipsCoverage } from './ipsCategories.ts';


// Hardening actions that only exist behind specific findings; their findings keep their own key.
const HIDDEN_TEMPLATES = new Set(TEMPLATES.filter((t) => t.hidden).map((t) => t.id));
/** A fix that is one of the protections on Hardening goes by that protection's name everywhere. */
const protectionOf = (templateId: string | undefined) => {
  const t = TEMPLATES.find((x) => x.id === templateId && !x.hidden);
  return t ? { id: t.id, title: t.title } : null;
};

/** ['a', 'b', 'c'] → "a, b and c". */
const joinAnd = (xs: string[]) => (xs.length > 1 ? `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}` : (xs[0] ?? ''));

type Obj = Record<string, unknown>;

const WEIGHT: Record<Severity, number> = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
const FINDING_CATEGORY: Record<TemplateCategory, FindingCategory> = {
  segmentation: 'segmentation', dns: 'dns', gateway: 'gateway', internet: 'firewall', ips: 'ips', exposure: 'exposure', wifi: 'wifi', blocklist: 'firewall',
};

// ---------------------------------------------------------------------------------
// Exposure (port forwards / UPnP)
// ---------------------------------------------------------------------------------

export function analyzeExposure(raw: RawSnapshot, model: FwModel, clientName: (ip: string) => string | null): ExposureItem[] {
  const out: ExposureItem[] = [];
  for (const pf of raw.portForwards) {
    const enabled = pf.enabled !== false;
    const dstPorts = String(pf.dst_port ?? '');
    const fwdPorts = String(pf.fwd_port ?? dstPorts);
    const ports = parsePorts(fwdPorts) ?? parsePorts(dstPorts);
    const services: string[] = [];
    let severity: Severity = 'low';
    let risk = 'Exposes a service on your network to the internet.';
    if (ports) {
      for (const [s, e] of ports.ivs) {
        for (let p = Number(s); p <= Number(e) && services.length < 8; p++) {
          const r = RISKY_EXPOSED_PORTS[p];
          if (r) {
            services.push(`${r.name} (${p})`);
            if (sevRank(r.severity) > sevRank(severity)) {
              severity = r.severity;
              risk = r.why;
            }
          } else if (Number(e) - Number(s) < 4) services.push(`${portName(p)}${portName(p).startsWith('port') ? '' : ` (${p})`}`);
        }
      }
      const width = ports.ivs.reduce((acc, [s, e]) => acc + Number(e - s) + 1, 0);
      if (width > 100) {
        severity = sevRank(severity) < sevRank('high') ? 'high' : severity;
        risk = `Forwards a large range of ${width} ports — almost certainly broader than needed.`;
      }
    }
    // A "restriction" to 0.0.0.0/0 or another huge range is no restriction at all.
    const srcSet = typeof pf.src === 'string' ? AddrSet.parse(pf.src) : null;
    const tooBroad = !!srcSet && (srcSet.v4.size() > 16_777_216n || !srcSet.v6.isEmpty());
    const srcLimited = !tooBroad && (pf.src_limiting_enabled === true || (typeof pf.src === 'string' && pf.src !== '' && pf.src !== 'any'));
    const source = srcLimited ? String(pf.src ?? pf.src_firewall_group_id ?? 'restricted') : null;
    if (srcLimited && sevRank(severity) > sevRank('low')) {
      severity = sevRank(severity) >= sevRank('critical') ? 'medium' : 'low';
      risk = `${risk} Source is restricted to ${source}, which reduces the risk considerably.`;
    }
    if (!enabled) severity = 'info';
    out.push({
      id: String(pf._id),
      kind: 'port-forward',
      name: String(pf.name ?? 'Unnamed port forward'),
      enabled,
      externalPort: dstPorts,
      internalTarget: `${pf.fwd}:${fwdPorts}`,
      internalName: clientName(String(pf.fwd ?? '')),
      protocol: String(pf.proto ?? 'tcp_udp').replace('_', '/').toUpperCase(),
      sourceRestriction: source,
      severity,
      risk: enabled ? risk : 'Disabled — not exposed right now.',
      services,
      fix:
        enabled && sevRank(severity) >= sevRank('medium')
          ? { templateId: 'port-forward', params: { portForwardId: String(pf._id), mode: 'disable' }, label: 'Disable forward' }
          : null,
    });
  }
  const usg = raw.settings.usg;
  if (usg && usg.upnp_enabled === true) {
    out.push({
      id: 'upnp',
      kind: 'upnp',
      name: 'UPnP / NAT-PMP',
      enabled: true,
      externalPort: 'any (on request)',
      internalTarget: 'any device',
      internalName: null,
      protocol: 'TCP/UDP',
      sourceRestriction: null,
      severity: 'medium',
      risk: 'Any device on your network can open ports to the internet without your approval. Malware uses this to expose itself.',
      services: [],
      fix: { templateId: 'disable-upnp', params: {}, label: 'Disable UPnP' },
    });
  }
  void model;
  return out.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
}

// ---------------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------------

export interface PostureInput {
  raw: RawSnapshot;
  model: FwModel;
  matrix: SegmentationMatrix;
  hygiene: HygieneIssue[];
  exposure: ExposureItem[];
  templates: TemplateStatus[];
  threats7d: ThreatSummary;
  /** Accepted risks by key. */
  accepted?: Map<string, RiskAcceptance>;
}

export function computePosture(inp: PostureInput): Posture {
  const { raw, model, matrix, hygiene, exposure, templates, threats7d } = inp;
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, 'id' | 'link' | 'key' | 'howTo' | 'acceptance' | 'protection'> & { link?: string | null; key?: string; howTo?: string | null }) =>
    findings.push({
      id: `${f.checkId}:${findings.length}`,
      link: null,
      howTo: null,
      acceptance: null,
      protection: protectionOf(f.fix?.templateId),
      ...f,
      // An issue a hardening action fixes shares that action's key, so accepting the risk in either place hides both.
      key: f.key ?? (f.fix && !HIDDEN_TEMPLATES.has(f.fix.templateId) ? `protection:${f.fix.templateId}` : f.checkId),
    });
  const tpl = (id: string) => templates.find((t) => t.templateId === id);

  // --- IPS -------------------------------------------------------------------------
  const ips = raw.settings.ips as Obj | undefined;
  if (!ips) {
    add({ checkId: 'ips-mode', severity: 'info', status: 'info', category: 'ips', title: 'IPS settings could not be read', summary: 'The intrusion prevention configuration is only available through the internal API, which did not respond.', why: '', evidence: [], fix: null });
  } else {
    const mode = String(ips.ips_mode ?? 'disabled');
    const allowed = threats7d.alerted;
    if (mode === 'disabled') {
      add({ checkId: 'ips-mode', severity: 'critical', status: 'fail', category: 'ips', title: 'Intrusion prevention is turned off', summary: 'Nothing inspects your traffic for attacks, malware callbacks or known-bad addresses.', why: 'The IPS is the only layer that recognises malicious traffic on otherwise-allowed connections.', evidence: [], fix: { templateId: 'ips-mode', params: { mode: 'ips' }, label: 'Turn on intrusion prevention (Notify and Block)' } });
    } else if (mode === 'ids') {
      add({
        checkId: 'ips-mode',
        severity: 'high',
        status: 'fail',
        category: 'ips',
        title: 'IPS only detects — it does not block',
        summary: allowed ? `${allowed.toLocaleString()} detections in the last 7 days were allowed through because the IPS is in "Notify" mode.` : 'Detected attacks are logged but still allowed through.',
        why: '"Notify" mode gives you a log of attacks, but every one of them reached its target.',
        evidence: [`Mode: Notify (ids)`],
        fix: { templateId: 'ips-mode', params: { mode: 'ips' }, label: 'Turn on intrusion prevention (Notify and Block)' },
      });
    } else {
      add({ checkId: 'ips-mode', severity: 'info', status: 'pass', category: 'ips', title: 'Intrusion prevention blocks threats', summary: 'IPS is in Notify and Block mode.', why: '', evidence: [], fix: null });
    }
    const cov = ipsCoverage(ips);
    const missing = cov.missing.map((m) => m.name);
    const groups = [...new Set(cov.missing.flatMap((m) => (m.group ? [m.group] : [])))];
    if (mode !== 'disabled' && missing.length) {
      add({
        checkId: 'ips-categories',
        severity: 'low',
        status: 'warn',
        category: 'ips',
        title: cov.grouped
          ? `${missing.length} recommended detection${missing.length === 1 ? ' is' : 's are'} off`
          : `${missing.length} recommended threat categor${missing.length === 1 ? 'y isn’t' : 'ies aren’t'} checked`,
        summary: `Intrusion prevention doesn't check for: ${joinAnd(missing)}.`,
        why: 'Signatures in categories that are off are never checked, so those attacks pass unnoticed.',
        evidence: cov.grouped ? [`Active Detections in UniFi: ${groupCounts(cov)}`] : [`UniFi has ${cov.enabled} categor${cov.enabled === 1 ? 'y' : 'ies'} switched on.`],
        fix: null,
        howTo: cov.grouped
          ? `In UniFi Network, open Settings → CyberSecure → Protection → Intrusion Prevention → Active Detections and switch on the rest of ${joinAnd(groups)}. Peer to peer and Tor can stay off: they flag file sharing and anonymous browsing, not attacks. More detections use more of the gateway’s memory and CPU.`
          : 'In UniFi Network, open Settings → Security (Threat Management on older versions) → Intrusion Prevention and switch these categories on. More categories use more of the gateway’s memory and CPU.',
      });
    } else if (mode !== 'disabled' && cov.grouped) {
      add({ checkId: 'ips-categories', severity: 'info', status: 'pass', category: 'ips', title: 'Every recommended detection is on', summary: `Active Detections in UniFi: ${groupCounts(cov)}.`, why: '', evidence: [], fix: null });
    }
    // Honeypots: fake devices that nothing legitimate ever contacts.
    if (mode !== 'disabled') {
      const pots = new Set((Array.isArray(ips.honeypot) ? (ips.honeypot as Obj[]) : []).map((h) => String(h.network_id)));
      const bare = model.networks.filter((n) => n.enabled && !n.isTest && isUntrusted(n.role) && !pots.has(String(n.raw._legacyId ?? n.id)));
      if (bare.length) {
        add({
          checkId: 'honeypot',
          severity: 'low',
          status: 'warn',
          category: 'ips',
          title: `No honeypot on ${joinAnd(bare.map((n) => n.name))}`,
          summary: 'A honeypot is a fake device that nothing legitimate ever contacts, so any connection to it means something on that network is probing for victims.',
          why: 'It is free and almost never raises false alarms, so a compromised device is caught early.',
          evidence: [],
          fix: null,
          howTo: 'In UniFi Network, open Settings → CyberSecure (Security on older versions) → Honeypot and add an unused address outside the DHCP range on each network named above.',
        });
      }
    }
  }

  // --- Segmentation ------------------------------------------------------------------
  const nameOf = (id: string) => matrix.endpoints.find((e) => e.id === id)?.name ?? id;
  const risky = matrix.cells.filter((c) => c.risk === 'risk' && c.to !== 'gateway' && c.to !== 'internet');
  const bySrc = new Map<string, typeof risky>();
  for (const c of risky) bySrc.set(c.from, [...(bySrc.get(c.from) ?? []), c]);
  for (const [src, cells] of bySrc) {
    const net = model.networks.find((n) => n.id === src);
    const dsts = cells.map((c) => nameOf(c.to));
    const role = net ? roleLabel(net.role) : null;
    const who = role && !nameOf(src).toLowerCase().includes(role.toLowerCase()) ? `${role} devices on ${nameOf(src)}` : `Devices on ${nameOf(src)}`;
    add({
      checkId: 'segmentation',
      key: `segmentation:${src}`,
      severity: net?.role === 'guest' ? 'critical' : 'high',
      status: 'fail',
      category: 'segmentation',
      title: `${nameOf(src)} can reach ${dsts.join(', ')}`,
      summary: `${who} can start connections to ${dsts.join(', ')} — nothing in your firewall stops them.`,
      why: 'If any device on this network is compromised, the attacker can move straight to your more trusted devices.',
      evidence: cells.map((c) => `${nameOf(c.from)} → ${nameOf(c.to)}: ${c.summary}`),
      fix: { templateId: 'isolate-networks', params: { sources: [src], destinations: cells.map((c) => c.to) }, label: `Isolate ${nameOf(src)}` },
      link: '/firewall/segmentation',
    });
  }
  const partial = matrix.cells.filter((c) => c.risk === 'warn' && c.to !== 'gateway' && c.to !== 'internet');
  if (partial.length) {
    add({
      checkId: 'segmentation-partial',
      severity: 'low',
      status: 'warn',
      category: 'segmentation',
      title: `${partial.length} network path${partial.length === 1 ? ' is' : 's are'} only partly blocked`,
      summary: 'Some traffic between less-trusted and trusted networks is allowed by exceptions. Check that each exception is intentional.',
      why: 'Exceptions are fine when deliberate, but each one is a path an attacker can use.',
      evidence: partial.map((c) => `${nameOf(c.from)} → ${nameOf(c.to)}: ${c.summary}`),
      fix: null,
      link: '/firewall/segmentation',
    });
  }
  if (!risky.length && !partial.length && matrix.cells.length) {
    add({ checkId: 'segmentation', severity: 'info', status: 'pass', category: 'segmentation', title: 'Untrusted networks are isolated', summary: 'No untrusted network can start connections to a trusted one.', why: '', evidence: [], fix: null, link: '/firewall/segmentation' });
  }
  if (model.networks.length <= 1 && model.networks.length) {
    add({ checkId: 'single-network', severity: 'medium', status: 'warn', category: 'segmentation', title: 'Everything is on one network', summary: 'All devices share a single network, so a compromised smart-home device can reach your computers directly.', why: 'Separate VLANs for IoT, cameras and guests are the single most effective home-network hardening step.', evidence: [], fix: null });
  }

  // Gateway management
  // Test networks exist to try things on, so they never count as findings.
  const isTestNet = (id: string) => model.networks.some((n) => n.id === id && n.isTest);
  const gwCells = matrix.cells.filter((c) => c.to === 'gateway' && c.fix?.templateId === 'protect-gateway' && !isTestNet(c.from));
  if (gwCells.length) {
    const open = gwCells.map((c) => {
      const net = model.networks.find((n) => n.id === c.from);
      return { name: nameOf(c.from), services: net ? reachableGatewayMgmt(model, net) : [] };
    });
    add({
      checkId: 'gateway-mgmt',
      severity: 'medium',
      status: 'fail',
      category: 'gateway',
      title: `Untrusted networks can reach the gateway's admin interfaces`,
      summary: `${joinAnd(open.map((o) => o.name))} can reach ${joinAnd([...new Set(open.flatMap((o) => o.services))])} on your gateway.`,
      why: 'A compromised IoT device or guest should never get a login prompt for the device that controls your network.',
      evidence: open.map((o) => `${o.name} → Gateway: ${joinAnd(o.services)} reachable`),
      fix: { templateId: 'protect-gateway', params: { networks: gwCells.map((c) => c.from) }, label: 'Lock down gateway management' },
    });
  }

  // --- DNS -----------------------------------------------------------------------------
  const dns = tpl('block-external-dns');
  if (dns && dns.state !== 'applied' && dns.state !== 'unknown' && dns.state !== 'not-applicable') {
    const open = dns.targets.filter((t) => t.state !== 'covered' && !isTestNet(t.id));
    const untrustedOpen = open.filter((t) => isUntrusted(model.networks.find((n) => n.id === t.id)?.role ?? 'other'));
    if (open.length) add({
      checkId: 'dns-bypass',
      severity: untrustedOpen.length ? 'medium' : 'low',
      status: 'fail',
      category: 'dns',
      title: 'Devices can bypass your DNS',
      summary: `${open.map((t) => t.name).join(', ')} can use any DNS server on the internet, skipping your gateway's filtering and logging.`,
      why: 'Malware and many IoT devices hard-code public resolvers to dodge filtering.',
      evidence: open.map((t) => `${t.name}: ${t.detail}`),
      fix: { templateId: 'block-external-dns', params: dns.suggestedParams, label: 'Force devices to use your DNS' },
    });
  }

  // --- Exposure --------------------------------------------------------------------------
  for (const e of exposure.filter((x) => x.kind === 'port-forward' && x.enabled && sevRank(x.severity) >= sevRank('medium'))) {
    add({
      checkId: 'port-forward',
      key: `port-forward:${e.id}`,
      severity: e.severity,
      status: 'fail',
      category: 'exposure',
      title: `Port forward “${e.name}” exposes ${e.services.length ? e.services.join(', ') : `port ${e.externalPort}`}`,
      summary: `${e.internalName ?? e.internalTarget} is reachable from ${e.sourceRestriction ? e.sourceRestriction : 'the entire internet'} on port ${e.externalPort}.`,
      why: e.risk,
      evidence: [`${e.protocol} ${e.externalPort} → ${e.internalTarget}`],
      fix: e.fix,
      link: '/firewall/exposure',
    });
  }
  const others = exposure.filter((x) => x.kind === 'port-forward' && x.enabled && sevRank(x.severity) < sevRank('medium'));
  if (others.length) {
    add({ checkId: 'port-forward-other', severity: 'info', status: 'info', category: 'exposure', title: `${others.length} other port forward${others.length === 1 ? '' : 's'} active`, summary: others.map((o) => `${o.name} (${o.externalPort})`).join(', '), why: 'Each forward is reachable from the internet; keep the software behind it patched.', evidence: [], fix: null, link: '/firewall/exposure' });
  }
  const upnp = exposure.find((x) => x.kind === 'upnp');
  if (upnp) add({ checkId: 'upnp', severity: 'medium', status: 'fail', category: 'exposure', title: 'UPnP is enabled', summary: upnp.risk, why: 'Ports opened by UPnP are invisible unless you go looking for them.', evidence: [], fix: upnp.fix });

  // --- Wi-Fi -----------------------------------------------------------------------------
  const guestNetIds = new Set(model.networks.filter((n) => n.role === 'guest').flatMap((n) => [n.id, String(n.raw._legacyId ?? '')]));
  for (const w of raw.wlans.filter((x) => x.enabled !== false)) {
    const name = String(w.name);
    const guest = w.is_guest === true || guestNetIds.has(String(w.networkconf_id));
    const sec = String(w.security ?? '');
    if (sec === 'open') {
      if (guest && w.l2_isolation !== true) {
        add({ checkId: 'wifi-open-guest', key: `wifi-open-guest:${w._id}`, severity: 'high', status: 'fail', category: 'wifi', title: `Open guest Wi-Fi “${name}” without client isolation`, summary: 'Anyone nearby can join, see every other guest device and attack it.', why: 'Open networks are not encrypted; isolation at least stops guests attacking each other.', evidence: [], fix: { templateId: 'guest-wifi-isolation', params: {}, label: 'Isolate clients on guest Wi-Fi' } });
      } else if (!guest) {
        add({ checkId: 'wifi-open', key: `wifi-open:${w._id}`, severity: 'critical', status: 'fail', category: 'wifi', title: `Wi-Fi “${name}” has no password`, summary: 'It is not a guest network, so anyone nearby lands on an internal network.', why: 'Unencrypted, unauthenticated access to an internal network.', evidence: [], fix: null });
      }
    } else if (sec === 'wep') {
      add({ checkId: 'wifi-wep', key: `wifi-wep:${w._id}`, severity: 'critical', status: 'fail', category: 'wifi', title: `Wi-Fi “${name}” uses WEP`, summary: 'WEP can be cracked in minutes.', why: 'Broken encryption.', evidence: [], fix: null });
    } else if (sec === 'wpapsk') {
      if (w.wpa3_support !== true && w.pmf_mode !== 'required' && !guest) {
        add({
          checkId: 'wifi-wpa2',
          key: `wifi-wpa2:${w._id}`,
          severity: 'low',
          status: 'warn',
          category: 'wifi',
          title: `Wi-Fi “${name}” uses WPA2 only`,
          summary: 'WPA2 passwords can be cracked offline from a captured login. WPA3 devices are not affected.',
          why: 'Use a long passphrase at minimum, and WPA3 wherever your devices support it.',
          evidence: [],
          fix: null,
          howTo: `In UniFi Network, open Settings → WiFi → “${name}” and set the security protocol to WPA2/WPA3. Leave PMF on Optional so older devices keep connecting, then check that everything on it reconnects.`,
        });
      }
      if (guest && w.l2_isolation !== true) {
        add({ checkId: 'wifi-guest-isolation', key: `wifi-guest-isolation:${w._id}`, severity: 'low', status: 'warn', category: 'wifi', title: `Guest Wi-Fi “${name}” does not isolate clients`, summary: 'Guests can see and connect to each other\'s devices.', why: 'Client isolation stops one infected guest device from attacking the others.', evidence: [], fix: { templateId: 'guest-wifi-isolation', params: {}, label: 'Isolate clients on guest Wi-Fi' } });
      }
    }
  }

  // --- Firmware / devices ----------------------------------------------------------------
  const upgradable = raw.devices.filter((d) => d.upgradable === true);
  if (upgradable.length) {
    add({
      checkId: 'firmware',
      severity: upgradable.some((d) => ['udm', 'ugw', 'uxg'].includes(String(d.type))) ? 'medium' : 'low',
      status: 'fail',
      category: 'devices',
      title: `${upgradable.length} device${upgradable.length === 1 ? ' has' : 's have'} firmware updates`,
      summary: upgradable.map((d) => `${d.name} (${d.version} → ${d.upgrade_to_firmware ?? 'newer'})`).join(', '),
      why: 'Firmware updates fix security vulnerabilities in your network gear.',
      evidence: [],
      fix: null,
      howTo: 'In UniFi Network, open UniFi Devices and update each device listed, or turn on automatic updates so it happens overnight.',
    });
  }
  const mgmt = raw.settings.mgmt;
  if (mgmt && mgmt.x_ssh_enabled === true && mgmt.x_ssh_auth_password_enabled !== false) {
    add({
      checkId: 'device-ssh',
      severity: 'low',
      status: 'warn',
      category: 'devices',
      title: 'Device SSH is on with password login',
      summary: 'Every UniFi access point and switch accepts SSH logins with a password.',
      why: 'Most people never need SSH on their devices. If you do, SSH keys are much safer than a password.',
      evidence: [],
      fix: null,
      howTo: 'In UniFi Network, open Settings → Control Plane → Console (System on older versions) → Device SSH Authentication. Turn it off, or add an SSH key and turn off password login.',
    });
  }

  // --- Firewall hygiene ----------------------------------------------------------------
  const dup = hygiene.filter((h) => h.kind === 'duplicate' || h.kind === 'redundant');
  const shadow = hygiene.filter((h) => h.kind === 'shadowed');
  const broad = hygiene.filter((h) => h.kind === 'broad-allow' && sevRank(h.severity) >= sevRank('high'));
  for (const b of broad) add({ checkId: 'broad-allow', key: `broad-allow:${b.id}`, severity: b.severity, status: 'fail', category: 'firewall', title: b.title, summary: b.detail, why: 'Overly broad allow rules undo the protection of everything below them.', evidence: [], fix: null, link: '/firewall/hygiene' });
  if (shadow.length) add({ checkId: 'shadowed', severity: 'low', status: 'warn', category: 'firewall', title: `${shadow.length} rule${shadow.length === 1 ? ' never takes' : 's never take'} effect`, summary: shadow.map((s) => s.title).join('; '), why: 'A block rule hidden behind an allow rule gives a false sense of security.', evidence: [], fix: null, link: '/firewall/hygiene' });
  if (dup.length) add({ checkId: 'duplicates', severity: 'info', status: 'warn', category: 'firewall', title: `${dup.length} duplicate or redundant rule${dup.length === 1 ? '' : 's'}`, summary: dup.map((s) => s.title).join('; '), why: 'Redundant rules make the firewall harder to audit.', evidence: [], fix: null, link: '/firewall/hygiene' });

  // --- Threat activity -----------------------------------------------------------------
  for (const s of threats7d.suspects.slice(0, 5)) {
    add({
      checkId: 'suspect-device',
      key: `suspect-device:${s.ip}`,
      severity: s.severity === 'critical' ? 'critical' : 'high',
      status: 'fail',
      category: 'threats',
      title: `${s.name ?? s.ip} may be compromised`,
      summary: `${s.count} outbound/internal detection${s.count === 1 ? '' : 's'} (${s.categories.join(', ')}) from this device in the last 7 days.`,
      why: 'Attack or malware traffic STARTED by one of your own devices usually means it is infected.',
      evidence: [`${s.ip}${s.network ? ` on ${s.network}` : ''}`],
      fix: null,
      link: `/investigate/${encodeURIComponent(s.ip)}`,
    });
  }

  // --- Unfinished protections --------------------------------------------------------------
  // Hardening's "Worth doing" and this list agree: a protection that no check above points to is listed on its own.
  const linked = new Set(findings.flatMap((f) => (f.fix ? [f.fix.templateId] : [])));
  for (const st of templates) {
    const t = TEMPLATES.find((x) => x.id === st.templateId);
    if (!t || t.hidden || linked.has(t.id) || (st.state !== 'partial' && st.state !== 'not-applied')) continue;
    const todo = st.targets.filter((x) => !x.test && (x.state === 'partial' || x.state === 'missing'));
    add({
      checkId: `protection-${t.id}`,
      severity: 'low',
      status: 'warn',
      category: FINDING_CATEGORY[t.category],
      title: t.title,
      summary: `${t.summary}${todo.length ? ` Not done yet for ${joinAnd(todo.map((x) => x.name))}.` : ''}`,
      why: t.why,
      evidence: todo.slice(0, 3).map((x) => `${x.name}: ${x.detail}`),
      fix: { templateId: t.id, params: st.suggestedParams, label: t.title },
    });
  }

  // --- Risk acceptance ---------------------------------------------------------------------
  // Accepted on its own, or through the protection that fixes it (accepting a whole protection on Hardening).
  const viaProtection = (f: Finding) => (f.fix && !HIDDEN_TEMPLATES.has(f.fix.templateId) ? inp.accepted?.get(`protection:${f.fix.templateId}`) : undefined);
  for (const f of findings) f.acceptance = inp.accepted?.get(f.key) ?? viaProtection(f) ?? null;
  const open = findings.filter((f) => f.status === 'fail' || f.status === 'warn');

  // --- Score -----------------------------------------------------------------------------
  // Accepted issues are the owner's informed decision, so they no longer count against the score.
  const failing = open.filter((f) => !f.acceptance);
  // Each issue removes a share of the remaining score, so fixing anything always moves the needle.
  let factor = 1;
  for (const f of failing) factor *= 1 - WEIGHT[f.severity] / 100;
  const score = Math.round(Math.max(0, Math.min(100, factor * 100)));
  const grade: Posture['grade'] = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 55 ? 'D' : 'F';
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const f of failing) counts[f.severity]++;
  findings.sort((a, b) => Number(a.status === 'pass') - Number(b.status === 'pass') || sevRank(b.severity) - sevRank(a.severity));
  const acceptances = new Set(open.flatMap((f) => (f.acceptance ? [f.acceptance.key] : [])));
  return { score, grade, findings, counts, passed: findings.filter((f) => f.status === 'pass').length, failed: failing.length, accepted: acceptances.size, checkedAt: Date.now() };
}
