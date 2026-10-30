// API contract shared by the server and the web UI.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

// ---------------------------------------------------------------------------------
// App status / settings
// ---------------------------------------------------------------------------------

export type FirewallMode = 'zone' | 'legacy' | 'unknown';

/**
 * How much the console may change on the controller:
 *  - read-only:    nothing (plans can still be previewed)
 *  - test-network: only new rules whose source is a dedicated test network ("SC-Test…"),
 *                  plus creating that test network; existing rules and settings are never touched
 *  - full:         everything
 */
export type WriteMode = 'read-only' | 'test-network' | 'full';
export const TEST_NETWORK_PREFIX = 'SC-Test';

/** Shortest password the sign-in account accepts. */
export const PASSWORD_MIN_LENGTH = 12;

export interface CapabilityReport {
  key: string;
  label: string;
  ok: boolean;
  detail: string;
}

// ---------------------------------------------------------------------------------
// Environments (one UniFi site each)
// ---------------------------------------------------------------------------------

export interface EnvInput {
  name?: string;
  url?: string;
  apiKey?: string;
  site?: string;
  verifyTls?: boolean;
  color?: string;
  writeMode?: WriteMode;
  /** The certificate key (CertInfo.spki) the owner saw when testing the connection, to be pinned on save. */
  trustCert?: string;
}

/** A console's TLS certificate as the app saw it. */
export interface CertInfo {
  /** SHA-256 of the certificate's public key (base64): what the app pins. */
  spki: string;
  /** SHA-256 fingerprint of the whole certificate, as a browser shows it (AA:BB:…). */
  sha256: string;
  subject: string;
  issuer: string;
  validTo: string;
  selfSigned: boolean;
}

export interface TlsPin extends CertInfo {
  pinnedAt: number;
}

/** How the connection to a console is protected. */
export interface EnvTls {
  /** ca: checked against public certificate authorities; pinned: only the trusted certificate is accepted;
   *  pending: trusted at the next connection; plain: http, not encrypted. */
  mode: 'ca' | 'pinned' | 'pending' | 'plain';
  pin: TlsPin | null;
  /** The certificate the console presented instead of the trusted one; the connection is refused until reviewed. */
  mismatch: CertInfo | null;
}

export interface EnvSummary {
  id: string;
  name: string;
  color: string;
  url: string | null;
  site: string;
  verifyTls: boolean;
  writeMode: WriteMode;
  effectiveWriteMode: WriteMode;
  apiKeySet: boolean;
  apiKeyHint: string | null;
  connected: boolean;
  version: string | null;
  siteName: string | null;
  firewallMode: FirewallMode;
  lastError: string | null;
  tls: EnvTls | null;
}

/** A console reachable with a unifi.ui.com (Site Manager) API key. */
export interface CloudConsole {
  /** Site Manager host id, used in the connector address. */
  id: string;
  /** The environment URL for this console (unifi.ui.com's connector). */
  url: string;
  name: string;
  model: string | null;
  version: string | null;
  /** null when unifi.ui.com does not say. */
  online: boolean | null;
  owner: boolean;
  /** Whether the console runs UniFi Network (null when unknown). */
  hasNetwork: boolean | null;
}

export interface EnvTestResult {
  ok: boolean;
  message: string;
  version: string | null;
  firewallMode: FirewallMode | null;
  capabilities: CapabilityReport[];
  /** All sites on that controller, so each one can be added as its own environment. */
  sites: { internalReference: string; name: string }[];
  /** The certificate a self-signed console presented, for the owner to check before it is trusted. */
  cert?: CertInfo | null;
  /** It differs from the certificate trusted for this environment. */
  certChanged?: boolean;
}

export interface FleetRow {
  env: EnvSummary;
  score: number | null;
  grade: string | null;
  failed: number | null;
  critical: number;
  threats24h: number;
  blocked24h: number;
  alerted24h: number;
  clients: number | null;
  rxBps: number | null;
  txBps: number | null;
}

export interface AppStatus {
  /** All environments; the rest of this object describes `envId`. */
  environments: EnvSummary[];
  envId: string | null;
  configured: boolean;
  connected: boolean;
  readOnly: boolean;
  writeMode: WriteMode;
  authRequired: boolean;
  authenticated: boolean;
  /** Before signing in: no account exists yet, so this visit creates it. */
  setupRequired?: boolean;
  /** The signed-in account. */
  username?: string | null;
  controller: {
    url: string | null;
    version: string | null;
    kind: 'unifi-os' | 'self-hosted' | 'cloud' | null;
    site: string;
    siteDescription: string | null;
    firewallMode: FirewallMode;
    gatewayModel: string | null;
  };
  capabilities: CapabilityReport[];
  lastError: string | null;
  lastRefresh: number | null;
  intel: { providers: IntelProviderSettings; abuseipdb: boolean; greynoise: boolean; geoDb: boolean };
}

/** Global settings (connection details live on each environment). */
export interface SettingsView {
  intel: IntelProviderSettings;
  abuseipdbKeySet: boolean;
  greynoiseKeySet: boolean;
  threatRetentionDays: number;
  geoDb: GeoDbStatus;
}

export interface IntelProviderSettings {
  /** Regional internet registries via the IANA RDAP bootstrap (ownership, abuse contact). */
  rdap: boolean;
  /** Tor Project bulk exit list (downloaded as a whole; no per-IP queries). */
  tor: boolean;
  /** ip-api.com (geo / ASN / hosting flags). Free tier is non-commercial use only. */
  ipapi: boolean;
  /** Shodan InternetDB (open ports / vulnerabilities seen by Shodan scans). */
  internetdb: boolean;
}

export interface GeoDbStatus {
  installed: boolean;
  edition: string | null;
  builtAt: string | null;
  sizeBytes: number | null;
  downloading: boolean;
  error: string | null;
}

export interface SettingsUpdate {
  intel?: Partial<IntelProviderSettings>;
  abuseipdbKey?: string;
  greynoiseKey?: string;
  threatRetentionDays?: number;
}

// ---------------------------------------------------------------------------------
// Threats
// ---------------------------------------------------------------------------------

export type ThreatDirection = 'inbound' | 'outbound' | 'internal' | 'unknown';
export type ThreatFamily = 'recon' | 'credential' | 'reputation' | 'anonymizer' | 'exploit' | 'web' | 'malware' | 'dos' | 'policy' | 'info' | 'protocol' | 'other';

export interface ThreatCategory {
  key: string;
  name: string;
  family: ThreatFamily;
  defaultSeverity: Severity;
  summary: string;
  description: string;
  whyItMatters: string;
  inbound: string;
  outbound: string;
  internal: string;
  falsePositives?: string;
  recommendations: string[];
  mitre?: { id: string; name: string; tactic: string }[];
}

export interface LocalEndpoint {
  ip: string;
  mac: string | null;
  name: string | null;
  network: string | null;
  networkId: string | null;
  vlan: number | null;
  /** true when the IP belongs to a client/device the controller knows about */
  known: boolean;
}

export interface ThreatEvent {
  id: string;
  ts: number;
  source: string;
  signature: string;
  signatureId: number | null;
  headline: string;
  detail: string | null;
  categoryKey: string;
  categoryRaw: string | null;
  classtype: string | null;
  cves: string[];
  priority: number | null;
  severity: Severity;
  action: 'blocked' | 'alerted' | 'unknown';
  direction: ThreatDirection;
  srcIp: string;
  srcPort: number | null;
  dstIp: string;
  dstPort: number | null;
  proto: string | null;
  appProto: string | null;
  remoteIp: string | null;
  localIp: string | null;
  local: LocalEndpoint | null;
  remoteCountry: string | null;
  remoteOrg: string | null;
  meaning: string;
  advice: string;
  count: number;
}

export interface ThreatQuery {
  from?: number;
  to?: number;
  severity?: Severity[];
  direction?: ThreatDirection[];
  action?: ('blocked' | 'alerted' | 'unknown')[];
  category?: string[];
  ip?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

export interface ThreatSummary {
  range: { from: number; to: number };
  total: number;
  blocked: number;
  alerted: number;
  uniqueSources: number;
  bySeverity: Record<Severity, number>;
  byDirection: Record<ThreatDirection, number>;
  byCategory: { key: string; name: string; family: ThreatFamily; count: number; blocked: number; severity: Severity }[];
  topSignatures: { signature: string; headline: string; categoryKey: string; count: number; severity: Severity; lastSeen: number; blocked: number }[];
  topSources: { ip: string; count: number; country: string | null; org: string | null; lastSeen: number; severity: Severity; blocked: number; categories: string[]; direction: ThreatDirection }[];
  topTargets: { ip: string; name: string | null; network: string | null; count: number; severity: Severity }[];
  byCountry: { country: string; count: number }[];
  timeline: { t: number; total: number; blocked: number; critical: number; high: number; medium: number; low: number; info: number }[];
  bucketMs: number;
  suspects: { ip: string; name: string | null; network: string | null; count: number; categories: string[]; severity: Severity; lastSeen: number }[];
}

// ---------------------------------------------------------------------------------
// IP intelligence
// ---------------------------------------------------------------------------------

export type IpScope = 'public' | 'private' | 'cgnat' | 'loopback' | 'link-local' | 'multicast' | 'reserved' | 'documentation' | 'unspecified' | 'invalid';
export type IpVerdictLevel = 'malicious' | 'suspicious' | 'scanner' | 'cloud' | 'benign' | 'unknown' | 'internal';

export interface IpIntel {
  ip: string;
  version: 4 | 6;
  scope: IpScope;
  scopeLabel: string;
  local: LocalEndpoint | null;
  insideNetwork: { id: string; name: string; vlan: number | null } | null;
  reverseDns: string[];
  /** Reverse DNS names that resolve back to this address (forward-confirmed). Others are unverified. */
  reverseDnsVerified: string[];
  geo: { country: string | null; countryCode: string | null; region: string | null; city: string | null; lat: number | null; lon: number | null; timezone: string | null } | null;
  network: { asn: number | null; asName: string | null; org: string | null; isp: string | null; hosting: boolean | null; proxy: boolean | null; mobile: boolean | null } | null;
  registration: {
    name: string | null;
    handle: string | null;
    cidr: string | null;
    range: string | null;
    country: string | null;
    registrant: string | null;
    abuseEmail: string | null;
    registry: string | null;
    created: string | null;
    updated: string | null;
  } | null;
  exposure: { ports: number[]; tags: string[]; vulns: string[]; hostnames: string[]; cpes: string[] } | null;
  reputation: {
    tor: boolean | null;
    abuseipdb: { score: number; totalReports: number; distinctUsers: number | null; lastReportedAt: string | null; usageType: string | null; domain: string | null } | null;
    greynoise: { classification: string | null; noise: boolean; riot: boolean; name: string | null; lastSeen: string | null; link: string | null } | null;
  };
  knownScanner: { name: string; description: string } | null;
  verdict: { level: IpVerdictLevel; score: number; summary: string; reasons: string[] };
  activity: {
    events: number;
    blocked: number;
    firstSeen: number | null;
    lastSeen: number | null;
    directions: Record<ThreatDirection, number>;
    signatures: { signature: string; headline: string; categoryKey: string; count: number; severity: Severity }[];
    peers: { ip: string; name: string | null; count: number }[];
    recent: ThreatEvent[];
  };
  blocking: { inbound: ReachVerdict; outbound: ReachVerdict; rules: { id: string; name: string; action: RuleAction }[] } | null;
  /** Where each fact came from, and when it was retrieved (null = local database). */
  sources: { name: string; ok: boolean; cached: boolean; error: string | null; at: number | null }[];
  fetchedAt: number;
  /** Your own devices only: enabled port forwards that make this address reachable from the internet. */
  exposedBy?: { id: string; name: string; what: string; severity: Severity; limited: boolean }[];
  /** Your own devices only: the name UniFi gave this address in its detections, when no connected client has it now. */
  seenAs?: string | null;
}

// ---------------------------------------------------------------------------------
// Firewall model / segmentation
// ---------------------------------------------------------------------------------

export type RuleAction = 'allow' | 'block' | 'reject';
export type NetworkRole = 'trusted' | 'management' | 'servers' | 'storage' | 'iot' | 'cameras' | 'guest' | 'voip' | 'media' | 'kids' | 'lab' | 'dmz' | 'vpn' | 'other';

export const NETWORK_ROLES: { value: NetworkRole; label: string; trust: number; description: string }[] = [
  { value: 'management', label: 'Management', trust: 4, description: 'Network gear and admin workstations' },
  { value: 'trusted', label: 'Trusted', trust: 3, description: 'Your own computers and phones' },
  { value: 'servers', label: 'Servers', trust: 3, description: 'NAS, home servers, self-hosted apps' },
  { value: 'storage', label: 'Storage (SAN)', trust: 3, description: 'iSCSI / NFS disk traffic between servers and storage only' },
  { value: 'voip', label: 'VoIP', trust: 2, description: 'Phones and PBX' },
  { value: 'media', label: 'Media', trust: 2, description: 'TVs, streaming boxes, consoles' },
  { value: 'kids', label: 'Kids', trust: 2, description: 'Devices with restricted access' },
  { value: 'lab', label: 'Lab', trust: 2, description: 'Internal test machines, not reachable from the internet' },
  { value: 'dmz', label: 'DMZ', trust: 1, description: 'Internet-facing servers (port forwards, reverse proxies)' },
  { value: 'iot', label: 'IoT', trust: 1, description: 'Smart-home devices, plugs, sensors' },
  { value: 'cameras', label: 'Cameras', trust: 1, description: 'Security cameras, doorbells, NVRs' },
  { value: 'guest', label: 'Guest', trust: 0, description: 'Visitors - internet only' },
  { value: 'vpn', label: 'VPN', trust: 3, description: 'Remote-access VPN clients' },
  { value: 'other', label: 'Other', trust: 2, description: 'Unclassified' },
];

export interface NetworkSummary {
  id: string;
  name: string;
  vlan: number | null;
  purpose: string;
  subnet: string | null;
  subnet6: string | null;
  gatewayIp: string | null;
  zoneId: string | null;
  zoneName: string | null;
  role: NetworkRole;
  roleSource: 'auto' | 'user';
  isolated: boolean;
  internetAccess: boolean;
  clientCount: number;
  dhcpDns: string[];
  enabled: boolean;
  isTest: boolean;
}

export interface ZoneSummary {
  id: string;
  name: string;
  key: string | null;
  networkIds: string[];
  networkNames: string[];
}

/** Plain direction of a rule: from the internet, to the internet, between your networks, or to the gateway itself. */
export type RuleDirection = 'inbound' | 'outbound' | 'internal' | 'gateway' | 'other';

export interface RuleView {
  id: string;
  name: string;
  system: 'zone' | 'legacy' | 'traffic';
  /** Zone names for zone-based rules; null for legacy rulesets. */
  srcZone: string | null;
  dstZone: string | null;
  direction: RuleDirection;
  enabled: boolean;
  predefined: boolean;
  managed: boolean;
  action: RuleAction;
  index: number;
  group: string;
  source: string;
  destination: string;
  service: string;
  states: string;
  ipVersion: string;
  sentence: string;
  logging: boolean;
  schedule: string | null;
  exact: boolean;
  notes: string[];
  raw: unknown;
}

export type ReachVerdict = 'allowed' | 'blocked' | 'partial' | 'self' | 'unknown';

export interface MatrixEndpoint {
  id: string;
  name: string;
  kind: 'network' | 'internet' | 'gateway';
  vlan: number | null;
  role: NetworkRole | null;
  subnet: string | null;
}

export interface FixAction {
  templateId: string;
  params: Record<string, unknown>;
  label: string;
}

export interface MatrixCell {
  from: string;
  to: string;
  verdict: ReachVerdict;
  expected: 'allow' | 'block' | 'either';
  risk: 'ok' | 'warn' | 'risk' | 'none';
  summary: string;
  explanation: string[];
  rules: { id: string; name: string; action: RuleAction | 'default'; effect: 'decides' | 'exception' | 'conditional' }[];
  fix: FixAction | null;
}

export interface SegmentationMatrix {
  firewallMode: FirewallMode;
  endpoints: MatrixEndpoint[];
  cells: MatrixCell[];
  notes: string[];
}

/** Connections the firewall blocked from one device on a path, from UniFi's traffic log. */
export interface BlockedGroup {
  /** Matrix endpoint ids, as in MatrixCell. */
  from: string;
  to: string;
  source: { ip: string; name: string | null };
  /** Null towards the internet, where destinations vary: see `examples`. */
  destination: { ip: string; name: string | null } | null;
  examples: string[];
  protocol: string;
  port: number | null;
  count: number;
  lastSeen: number;
  /** An allow rule that covers these devices but another port, or this port but another address. */
  nearMiss: { ruleId: string; ruleName: string; reason: string } | null;
}

export interface BlockedTraffic {
  from: number;
  to: number;
  /** False when the console keeps no traffic log (before Network 9.1) or it did not answer. */
  available: boolean;
  /** More was blocked than was read: counts are a lower bound. */
  truncated: boolean;
  /** Keyed "fromEndpointId>toEndpointId". Near misses come first in `groups`. */
  cells: Record<string, { total: number; nearMisses: number; groups: BlockedGroup[] }>;
}

export interface HygieneIssue {
  id: string;
  kind: 'redundant' | 'shadowed' | 'disabled' | 'broad-allow' | 'unresolved-ref' | 'duplicate' | 'no-effect';
  severity: Severity;
  title: string;
  detail: string;
  ruleIds: string[];
  ruleNames: string[];
}

/** One way into your network from the internet. */
export interface Door {
  id: string;
  kind: ExposureItem['kind'] | 'vpn-server' | 'site-vpn';
  name: string;
  /** What it opens, in plain words: "HTTPS (443) → NAS (192.168.1.10)". */
  detail: string;
  severity: Severity;
  /** Only some source addresses, or only people with VPN keys, can use it. */
  limited: boolean;
  /** Inbound detections aimed at the device behind it in the last 24 hours. */
  attacks: number;
}

export interface NewDevice {
  name: string | null;
  vendor: string | null;
  ip: string | null;
  network: string | null;
  firstSeen: number;
  wired: boolean;
  guest: boolean;
}

export interface DeviceIssue {
  name: string;
  model: string | null;
  issue: 'offline' | 'update';
  detail: string;
  /** When an offline device was last seen. */
  since: number | null;
}

/** The Overview cards beyond the score and attacks: ways in, new devices, this app's changes, UniFi devices. */
export interface OverviewExtras {
  doors: Door[];
  /** Null when the gateway settings could not be read. */
  upnp: boolean | null;
  /** Null when the controller does not report client details. */
  newDevices: NewDevice[] | null;
  changes: { recent: Pick<ChangeRecord, 'id' | 'ts' | 'title' | 'summary' | 'status'>[]; total: number };
  devices: DeviceIssue[];
}

export interface ExposureItem {
  id: string;
  kind: 'port-forward' | 'upnp' | 'wan-rule' | 'dmz';
  name: string;
  enabled: boolean;
  externalPort: string;
  internalTarget: string;
  internalName: string | null;
  protocol: string;
  sourceRestriction: string | null;
  severity: Severity;
  risk: string;
  services: string[];
  fix: FixAction | null;
}

export interface FirewallOverview {
  firewallMode: FirewallMode;
  networks: NetworkSummary[];
  zones: ZoneSummary[];
  rules: RuleView[];
  hygiene: HygieneIssue[];
  exposure: ExposureItem[];
  counts: { total: number; custom: number; enabled: number; managed: number; predefined: number };
  warnings: string[];
}

// ---------------------------------------------------------------------------------
// Posture / findings
// ---------------------------------------------------------------------------------

export type FindingCategory = 'ips' | 'segmentation' | 'dns' | 'exposure' | 'wifi' | 'gateway' | 'firewall' | 'threats' | 'devices';

/** An issue or protection the owner decided not to act on, with their reason. It no longer counts as a to-do. */
export interface RiskAcceptance {
  /** Shared by an issue and the protection that fixes it, so accepting either hides both. */
  key: string;
  kind: 'finding' | 'protection';
  title: string;
  reason: string;
  acceptedAt: number;
}

export interface Finding {
  id: string;
  /** Stable identity for risk acceptance ("protection:<template>" when a hardening action fixes it). */
  key: string;
  checkId: string;
  severity: Severity;
  status: 'fail' | 'warn' | 'pass' | 'info';
  category: FindingCategory;
  title: string;
  summary: string;
  why: string;
  evidence: string[];
  fix: FixAction | null;
  link: string | null;
  /** Steps to change it in UniFi itself, for things this console only reports on. */
  howTo: string | null;
  acceptance: RiskAcceptance | null;
  /** The Hardening protection that fixes it, under the one name it has everywhere. */
  protection: { id: string; title: string } | null;
}

export interface Posture {
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  findings: Finding[];
  counts: Record<Severity, number>;
  passed: number;
  failed: number;
  /** Issues the owner accepted; they no longer count against the score. */
  accepted: number;
  checkedAt: number;
}

// ---------------------------------------------------------------------------------
// Hardening
// ---------------------------------------------------------------------------------

export interface TemplateParamSpec {
  key: string;
  label: string;
  help?: string;
  type: 'networks' | 'boolean' | 'ips' | 'ports' | 'select' | 'text' | 'ip' | 'countries';
  required?: boolean;
  default?: unknown;
  options?: { value: string; label: string }[];
  /** Which networks should be pre-selected for 'networks' params. */
  preselect?: 'untrusted' | 'all' | 'none' | 'trusted';
  advanced?: boolean;
}

export type TemplateCategory = 'segmentation' | 'dns' | 'gateway' | 'internet' | 'ips' | 'exposure' | 'wifi' | 'blocklist';

export interface HardeningTemplate {
  id: string;
  title: string;
  category: TemplateCategory;
  icon: string;
  summary: string;
  description: string;
  why: string;
  caveats: string[];
  params: TemplateParamSpec[];
  kind: 'firewall' | 'setting';
  hidden?: boolean;
}

export type CoverageState = 'covered' | 'partial' | 'missing' | 'n/a';

export interface TemplateTarget {
  id: string;
  name: string;
  state: CoverageState;
  detail: string;
  rules: { id: string; name: string }[];
  /** A test network (or a pair involving one): shown, but not counted in the status. */
  test?: boolean;
}

export interface TemplateStatus {
  templateId: string;
  /** Set when the owner accepted not having this protection. */
  acceptance?: RiskAcceptance | null;
  state: 'applied' | 'partial' | 'not-applied' | 'not-applicable' | 'unknown';
  label: string;
  detail: string;
  targets: TemplateTarget[];
  suggestedParams: Record<string, unknown>;
}

export interface PlanOperation {
  id: string;
  kind: 'create' | 'update' | 'delete';
  objectType: 'firewall-policy' | 'firewall-rule' | 'firewall-group' | 'setting' | 'network' | 'wlan' | 'port-forward';
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  api: 'internal' | 'integration';
  path: string;
  body?: unknown;
  description: string;
  sentence?: string;
  before?: unknown;
  targetId?: string;
  /** Operation ids whose created object ids must be substituted into this body (e.g. a new group id). */
  dependsOn?: string[];
  /** Firewall rules: the rule field by field, as UniFi will show it. */
  detail?: RuleDetail;
  /** Ordering steps: the order they set. */
  order?: RuleOrder;
}

/** One side of a firewall rule as UniFi's rule editor shows it. */
export interface RuleSide {
  zone: string | null;
  match: string;
  ports: string | null;
}

/** A firewall rule field by field, as it will look in UniFi once the change is applied. */
export interface RuleDetail {
  change: 'create' | 'update' | 'delete';
  name: string;
  action: 'Block' | 'Allow' | 'Reject';
  enabled: boolean;
  source: RuleSide;
  destination: RuleSide;
  protocol: string;
  ipVersion: string;
  states: string;
  logging: boolean;
  description: string | null;
  /** Where it sits among the other rules. */
  position: string | null;
  /** For a changed rule: the fields that change. */
  changes?: { field: string; from: string; to: string }[];
}

/** The order an ordering step sets for one zone pair. */
export interface RuleOrder {
  pair: string;
  rules: { name: string; isNew: boolean }[];
}

export interface PlanAnalysisItem {
  target: string;
  status: 'already-covered' | 'will-extend' | 'will-create' | 'will-update' | 'conflict' | 'exception' | 'skipped' | 'info';
  message: string;
  rules: { id: string; name: string }[];
}

export interface ChangePlan {
  id: string;
  templateId: string;
  title: string;
  summary: string;
  /** The summary in the past tense, kept in the Change Log once applied. */
  doneSummary?: string;
  params: Record<string, unknown>;
  analysis: PlanAnalysisItem[];
  operations: PlanOperation[];
  warnings: string[];
  noop: boolean;
  /** Why a no-op plan has nothing to do when it isn't "already in place": the choices are incomplete, or it can't be done here. */
  state?: 'needs-input' | 'unavailable';
  strategy: 'extend' | 'create' | 'update' | 'mixed' | 'none';
  alternatives: { strategy: string; label: string; description: string }[];
  /** Set when the current write mode does not allow this plan to be applied. */
  blockedReason: string | null;
  /** The change-safety level the plan was checked against; applying under another level is refused. */
  madeIn?: WriteMode;
  createdAt: number;
}

export interface ChangeRecord {
  id: string;
  ts: number;
  planId: string;
  templateId: string;
  title: string;
  summary: string;
  status: 'applied' | 'failed' | 'partial' | 'undone';
  operations: (PlanOperation & { status: 'ok' | 'failed' | 'skipped' | 'undone'; error?: string; resultId?: string })[];
  undoable: boolean;
  undoneAt: number | null;
  error: string | null;
  /** Write mode in effect when the change was applied. */
  appliedMode?: WriteMode;
}

// ---------------------------------------------------------------------------------
// Live stats
// ---------------------------------------------------------------------------------

export interface LiveSample {
  t: number;
  rxBps: number | null;
  txBps: number | null;
  latencyMs: number | null;
  clients: number | null;
  cpu: number | null;
  mem: number | null;
}

export const LIVE_RANGES = ['5m', '30m', '1h', '24h', '7d', '30d'] as const;
export type LiveRange = (typeof LIVE_RANGES)[number];

/** Live statistics over a time range: averages per bucket, with the peaks hidden inside each average. */
export interface LiveTrend {
  range: LiveRange;
  from: number;
  to: number;
  /** Width of one point; 5 s means every sample is its own point. */
  bucketMs: number;
  points: (LiveSample & { rxMax: number | null; txMax: number | null })[];
  summary: {
    /** Oldest sample in the range: history only reaches back to when the app started keeping it. */
    since: number | null;
    peakRx: { bps: number; t: number } | null;
    peakTx: { bps: number; t: number } | null;
    rxBytes: number;
    txBytes: number;
    avgLatency: number | null;
    maxLatency: number | null;
    avgCpu: number | null;
    maxCpu: number | null;
    maxClients: number | null;
  };
}

export interface LiveSnapshot {
  t: number;
  wan: { rxBps: number | null; txBps: number | null; latencyMs: number | null; ip: string | null; isp: string | null; status: string | null; uptime: number | null } | null;
  gateway: { name: string | null; model: string | null; version: string | null; cpu: number | null; mem: number | null; tempC: number | null; uptime: number | null; upgradable: boolean } | null;
  clients: { total: number; wired: number; wireless: number; guest: number; vpn: number };
  devices: { total: number; online: number; offline: number; disabled: number; upgradable: number };
  threats: { lastHour: number; last24h: number; blocked24h: number };
}

export interface ClientRow {
  mac: string;
  name: string;
  ip: string | null;
  network: string | null;
  networkId: string | null;
  vlan: number | null;
  wired: boolean;
  guest: boolean;
  rxBps: number;
  txBps: number;
  /** Since the device last connected (see uptime), all traffic. */
  rxBytes: number;
  txBytes: number;
  /** Last 24 hours from UniFi's hourly report (whole hours, all traffic); null when unknown. */
  rx24h: number | null;
  tx24h: number | null;
  signal: number | null;
  uptime: number | null;
  oui: string | null;
  essid: string | null;
  firstSeen: number | null;
}

export interface NetworkLoad {
  id: string;
  name: string;
  vlan: number | null;
  clients: number;
  rxBps: number;
  txBps: number;
}

export interface LiveClients {
  t: number;
  clients: ClientRow[];
  networks: NetworkLoad[];
}

export type LiveEvent =
  | { type: 'snapshot'; data: LiveSnapshot; sample: LiveSample }
  | { type: 'threat'; data: ThreatEvent }
  | { type: 'config-changed'; data: { reason: string } };

// ---------------------------------------------------------------------------------
// Devices: clients in detail, identification, and the UniFi devices themselves
// ---------------------------------------------------------------------------------

export interface MakerDbStatus {
  installed: boolean;
  entries: number | null;
  downloadedAt: number | null;
  downloading: boolean;
  error: string | null;
}

/** A best guess at what a device is, with the clues behind it. */
export interface DeviceIdentity {
  guess: string | null;
  confidence: 'high' | 'medium' | 'low' | null;
  maker: string | null;
  makerSource: 'unifi' | 'registry' | null;
  privateAddress: boolean;
  clues: string[];
  /** Links the owner may open; only the maker half of the MAC address is in them. */
  lookups: { label: string; url: string }[];
}

/** Everything about one client device: who it is, how it is connected, its traffic and its security. */
export interface ClientDetail {
  mac: string;
  name: string;
  hostname: string | null;
  ip: string | null;
  ipv6: string[];
  network: { id: string | null; name: string | null; vlan: number | null; role: NetworkRole | null };
  connection: {
    wired: boolean;
    guest: boolean;
    /** The access point or switch it is connected to. */
    via: string | null;
    port: number | null;
    linkMbps: number | null;
    ssid: string | null;
    band: string | null;
    standard: string | null;
    channel: number | null;
    channelWidth: number | null;
    signal: number | null;
    rxRateMbps: number | null;
    txRateMbps: number | null;
    streams: string | null;
    retriesPct: number | null;
    experience: number | null;
  };
  uptime: number | null;
  firstSeen: number | null;
  lastSeen: number | null;
  traffic: { downBps: number; upBps: number; down24h: number | null; up24h: number | null; downSince: number; upSince: number; hourly: { t: number; down: number; up: number }[] };
  identity: DeviceIdentity;
  security: {
    /** Started attack-like traffic in the last 7 days. */
    suspect: boolean;
    exposedBy: { id: string; name: string; what: string; severity: Severity; limited: boolean }[];
    /** Last 30 days. */
    threats: { total: number; blocked: number; alerted: number; aimedAt: number; startedBy: number; recent: ThreatEvent[] };
    /** What its network can reach, from the segmentation analysis. */
    reach: { to: string; verdict: ReachVerdict; risk: 'ok' | 'warn' | 'risk' | 'none'; summary: string }[];
  };
}

/** A UniFi device (gateway, switch, access point) as the Devices page lists it. */
export interface UnifiDevice {
  mac: string;
  name: string;
  model: string | null;
  kind: 'gateway' | 'switch' | 'ap' | 'other';
  state: 'online' | 'offline' | 'disabled' | 'updating' | 'adopting' | 'other';
  ip: string | null;
  version: string | null;
  /** The firmware version waiting to be installed, if any. */
  update: string | null;
  /** No more firmware updates for this model. */
  endOfLife: boolean;
  uptime: number | null;
  lastSeen: number | null;
  clients: number | null;
  cpu: number | null;
  mem: number | null;
  tempC: number | null;
  uplink: { name: string | null; port: number | null; speedMbps: number | null; wireless: boolean } | null;
}

export interface UnifiDeviceDetail extends UnifiDevice {
  ports: { idx: number; name: string; up: boolean; enabled: boolean; speedMbps: number | null; fullDuplex: boolean | null; poeWatts: number | null; uplink: boolean; devices: number | null; downBps: number | null; upBps: number | null; errors: number | null }[];
  radios: { band: string; channel: number | null; width: number | null; txPower: number | null; clients: number | null; utilization: number | null; experience: number | null; retriesPct: number | null }[];
  poe: { usedW: number | null; maxW: number | null } | null;
  /** Clients connected through this device right now. */
  connected: { mac: string; name: string; ip: string | null; wired: boolean; port: number | null; ssid: string | null }[];
}
