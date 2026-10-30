// Which intrusion prevention categories are on, counted the way UniFi shows them.
//
// UniFi Network 9 and later show the categories as "Active Detections": five groups with one switch per category and
// "3 of 3" style counts (seen on Network 10.6 on a UDR7, whose 13 switches match its 11 enabled categories plus two
// off). Older versions list dozens of classic Emerging Threats categories instead; those are checked against the
// handful that matter most.

type Obj = Record<string, unknown>;

interface Detection {
  key: string;
  name: string;
  /** Peer to peer and Tor flag file sharing and anonymous browsing: usage policies, not attacks. */
  recommended: boolean;
}

export const ACTIVE_DETECTIONS: { group: string; items: Detection[] }[] = [
  {
    group: 'Botnets and Threat Intelligence',
    items: [
      { key: 'botcc', name: 'Botnet command & control', recommended: true },
      { key: 'dshield', name: 'DShield attacker list', recommended: true },
      { key: 'malicious-hosts', name: 'Malicious hosts', recommended: true },
    ],
  },
  {
    group: 'Viruses, Malware and Spyware',
    items: [
      { key: 'emerging-malware', name: 'Malware', recommended: true },
      { key: 'emerging-mobile', name: 'Mobile malware', recommended: true },
      { key: 'emerging-worm', name: 'Worms', recommended: true },
    ],
  },
  {
    group: 'Hacking and Exploits',
    items: [
      { key: 'emerging-exploit', name: 'Exploits', recommended: true },
      { key: 'emerging-shellcode', name: 'Shellcode', recommended: true },
      { key: 'emerging-useragent', name: 'Malicious user agents', recommended: true },
    ],
  },
  {
    group: 'Peer to Peer and Dark Web',
    items: [
      { key: 'emerging-p2p', name: 'Peer to peer', recommended: false },
      { key: 'tor', name: 'Tor', recommended: false },
      { key: 'dark-web-blocker-list', name: 'Dark web blocker', recommended: true },
    ],
  },
  { group: 'Protocol Vulnerabilities', items: [{ key: 'emerging-dns', name: 'DNS', recommended: true }] },
];

// Classic categories worth having on. Each counts as on when any of its keys is enabled.
const CLASSIC: [keys: string[], name: string][] = [
  [['emerging-malware'], 'Malware'],
  [['botcc', 'botcc-portgrouped', 'threatview-cs-c2'], 'Botnet command & control'],
  [['emerging-exploit', 'exploit-kit'], 'Exploits'],
  [['emerging-scan'], 'Scanning'],
  [['compromised', 'ciarmy', 'drop', 'dshield'], 'Known malicious addresses'],
  [['emerging-worm'], 'Worms'],
  [['phishing'], 'Phishing'],
  [['coinminer'], 'Crypto miners'],
  [['emerging-webserver', 'emerging-webapps'], 'Web server attacks'],
  [['emerging-attackresponse'], 'Signs of a successful attack'],
];

export interface IpsCoverage {
  /** The console shows Active Detections (Network 9 and later). */
  grouped: boolean;
  /** Per group, how many switches are on, as UniFi counts them (grouped consoles only). */
  groups: { group: string; on: number; total: number }[];
  /** Recommended categories that are off; on grouped consoles with the group to find them in. */
  missing: { name: string; group: string | null }[];
  enabled: number;
}

export function ipsCoverage(ips: Obj): IpsCoverage {
  const cats = Array.isArray(ips.enabled_categories) ? ips.enabled_categories.map(String) : [];
  const on = new Set(cats);
  // memory_optimized arrived with Network 9 together with Active Detections, as did these two lists.
  const grouped = typeof ips.memory_optimized === 'boolean' || on.has('malicious-hosts') || on.has('dark-web-blocker-list');
  if (!grouped) {
    // A console with most of the classic list on has made its own choice.
    const missing = cats.length >= 20 ? [] : CLASSIC.filter(([keys]) => !keys.some((k) => on.has(k))).map(([, name]) => ({ name, group: null }));
    return { grouped, groups: [], missing, enabled: cats.length };
  }
  return {
    grouped,
    groups: ACTIVE_DETECTIONS.map((g) => ({ group: g.group, on: g.items.filter((i) => on.has(i.key)).length, total: g.items.length })),
    missing: ACTIVE_DETECTIONS.flatMap((g) => g.items.filter((i) => i.recommended && !on.has(i.key)).map((i) => ({ name: i.name, group: g.group }))),
    enabled: cats.length,
  };
}

/** "Botnets and Threat Intelligence 3 of 3 · …", exactly as UniFi's Active Detections list reads. */
export function groupCounts(c: IpsCoverage): string {
  return c.groups.map((g) => `${g.group} ${g.on} of ${g.total}`).join(' · ');
}
