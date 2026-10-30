// Catalog of hardening actions offered in the UI.

import type { HardeningTemplate, TemplateParamSpec } from '../../../shared/types.ts';

export const TEMPLATES: HardeningTemplate[] = [
  {
    id: 'block-external-dns',
    title: 'Force devices to use your DNS',
    category: 'dns',
    icon: 'dns',
    kind: 'firewall',
    summary: 'Block DNS and DNS-over-TLS to internet servers, so nothing can bypass your gateway\'s DNS, ad-blocking or content filtering.',
    description:
      'Creates a block rule for TCP/UDP 53 (and optionally 853, DNS-over-TLS) from the selected networks to the internet. Devices keep resolving names through your gateway (or your own DNS server), which still forwards to the internet as usual.',
    why: 'Malware and many IoT devices hard-code public resolvers such as 8.8.8.8 to dodge filtering and logging. Forcing DNS through your gateway means your blocklists, DNS logs and content filters apply to every device.',
    caveats: [
      'DNS-over-HTTPS rides on port 443 and cannot be blocked by port; pair this with content filtering / app blocking if you need to stop DoH.',
      'If you run your own DNS server (Pi-hole, AdGuard Home) it is automatically exempted so it can still reach its upstream resolvers.',
    ],
    params: [
      { key: 'networks', label: 'Apply to networks', type: 'networks', required: true, preselect: 'all' },
      { key: 'includeDot', label: 'Also block DNS-over-TLS (port 853)', type: 'boolean', default: true },
      {
        key: 'allowedServers',
        label: 'Your own DNS servers (exempted)',
        type: 'ips',
        help: 'Internal DNS servers that must still reach upstream resolvers, e.g. a Pi-hole. Detected automatically from your DHCP DNS settings.',
        advanced: true,
      },
    ],
  },
  {
    id: 'isolate-networks',
    title: 'Isolate networks from each other',
    category: 'segmentation',
    icon: 'split',
    kind: 'firewall',
    summary: 'Stop devices on one network from starting connections to another network. Replies to connections you start still work.',
    description:
      'Creates block rules for NEW connections from each source network to each destination network. Because only new connections are blocked, your trusted devices can still reach into the isolated network (e.g. control a smart plug) and get replies.',
    why: 'Segmentation contains a compromise: if a smart TV or a guest laptop is taken over, the attacker cannot reach your computers, NAS or cameras from there.',
    caveats: [
      'Casting / AirPlay / printer discovery across networks needs mDNS and specific allow rules.',
      'Devices that must initiate connections into the protected network (e.g. a smart-home hub talking to a NAS) need an explicit allow rule above the block.',
    ],
    params: [
      { key: 'sources', label: 'Block traffic FROM', type: 'networks', required: true, preselect: 'untrusted' },
      { key: 'destinations', label: 'TO these networks', type: 'networks', required: true, preselect: 'trusted' },
    ],
  },
  {
    id: 'block-internet',
    title: 'Block internet access for a network',
    category: 'internet',
    icon: 'globe-lock',
    kind: 'firewall',
    summary: 'Keep local-only networks (cameras, NVRs, storage) from talking to the internet at all.',
    description: 'Creates a block rule for all traffic from the selected networks to the internet. DNS, DHCP and NTP served by the gateway keep working.',
    why: 'Many cheap cameras and IoT devices phone home to cloud services with poor security, or can be remotely exploited. Devices that only need local access should not have internet access.',
    caveats: ['Cloud features, remote apps and automatic firmware updates for those devices stop working.', 'UniFi Protect cameras talk to your console locally and keep working.'],
    params: [{ key: 'networks', label: 'Networks without internet', type: 'networks', required: true, preselect: 'none' }],
  },
  {
    id: 'protect-gateway',
    title: 'Lock down gateway management',
    category: 'gateway',
    icon: 'router',
    kind: 'firewall',
    summary: 'Block untrusted networks from reaching the router\'s admin interfaces (SSH and web UI) while DNS, DHCP and NTP keep working.',
    description: 'Creates a block rule from the selected networks to the gateway itself for the management ports only.',
    why: 'A compromised IoT device or guest should never be able to log in to (or attack) the device that controls your whole network.',
    caveats: ['If this console also runs UniFi Protect, do not apply this to your camera network unless Protect is on a different device.', 'Make sure you are not applying it to the network you manage UniFi from.'],
    params: [
      { key: 'networks', label: 'Networks to restrict', type: 'networks', required: true, preselect: 'untrusted' },
      { key: 'ports', label: 'Management ports', type: 'ports', default: '22,80,443', help: "SSH, HTTP and HTTPS (the console's web UI).", advanced: true },
    ],
  },
  {
    id: 'block-countries',
    title: 'Block countries you never deal with',
    category: 'exposure',
    icon: 'flag',
    kind: 'firewall',
    summary: 'Drop connections from countries you pick before they reach anything you expose to the internet, such as port forwards or a VPN server.',
    description:
      "Adds the countries to UniFi's own Region Blocking (Settings → Security), one list that filters incoming connections for your whole network. Without Region Blocking, or if you choose so, it creates a block rule for each zone you protect instead, matching new connections so replies to connections your own devices start keep working.",
    why: 'Exposed services are probed constantly from all over the world. If nobody you know ever connects from a country, blocking it cuts off a large share of that noise at almost no cost.',
    caveats: [
      'Country data comes from GeoIP and is not perfect, and attackers can also use servers in countries you allow.',
      'Anyone you know who travels to, or uses a VPN in, a blocked country is blocked too.',
    ],
    params: [
      { key: 'countries', label: 'Countries to block', type: 'countries', required: true, default: [], help: 'Pick countries you never expect connections from.' },
      // Options are the site's zones, filled in when the templates are served.
      {
        key: 'zones',
        label: 'Protect these zones',
        type: 'select',
        default: [],
        options: [],
        help: 'Only for “Firewall rules per zone”. Pre-selected: zones reachable from the internet through port forwards or a VPN server.',
        advanced: true,
      },
    ],
  },
  {
    id: 'block-risky-outbound',
    title: 'Block risky outbound services',
    category: 'internet',
    icon: 'ban',
    kind: 'firewall',
    summary: 'Stop devices from sending email directly (SMTP), using Windows file sharing, Telnet or IRC towards the internet.',
    description: 'Creates a block rule from the selected networks to the internet for legacy protocols that normal devices never need, but malware and spam bots love.',
    why: 'Infected devices send spam over port 25, leak credentials over SMB and talk to old-school botnet C2 over IRC. Blocking these has essentially no downside for home and small-business networks.',
    caveats: ['If you run a mail server, exclude its network (or add an allow rule for it).'],
    params: [
      { key: 'networks', label: 'Apply to networks', type: 'networks', required: true, preselect: 'all' },
      {
        key: 'services',
        label: 'Services',
        type: 'select',
        default: ['smtp', 'smb', 'telnet', 'irc'],
        options: [
          { value: 'smtp', label: 'SMTP (25) — direct email sending' },
          { value: 'smb', label: 'SMB / NetBIOS (137-139, 445)' },
          { value: 'telnet', label: 'Telnet (23, 2323)' },
          { value: 'irc', label: 'IRC (6660-6669, 6697)' },
          { value: 'tftp', label: 'TFTP (69)' },
        ],
      },
    ],
  },
  {
    id: 'block-ip',
    title: 'Block an IP address or range',
    category: 'blocklist',
    icon: 'shield-x',
    kind: 'firewall',
    summary: 'Drop all traffic to and from a specific address or range — e.g. a persistent attacker.',
    description:
      'Adds the address to a managed blocklist group. The first time, it also creates block rules that reference the group; every later block just adds a member to the same group, so rules never pile up.',
    why: 'Your IPS blocks individual attacks, but blocking a hostile source outright stops all further probing — including traffic that would not trigger a signature.',
    caveats: ['Blocking large ranges of shared cloud providers can break legitimate services hosted there.'],
    params: [
      { key: 'ips', label: 'IP addresses / CIDR ranges', type: 'ips', required: true },
      {
        key: 'direction',
        label: 'Direction',
        type: 'select',
        default: 'both',
        options: [
          { value: 'both', label: 'Both directions' },
          { value: 'inbound', label: 'Inbound only (from that address)' },
          { value: 'outbound', label: 'Outbound only (to that address)' },
        ],
      },
    ],
    hidden: true,
  },
  {
    id: 'ips-mode',
    title: 'Turn on intrusion prevention (Notify and Block)',
    category: 'ips',
    icon: 'shield',
    kind: 'setting',
    summary: 'Make the IPS drop malicious traffic instead of just reporting it.',
    description: 'Switches Intrusion Prevention from "Notify" (detect only) to "Notify and Block". Detected attacks, malware callbacks and known-bad addresses are dropped automatically.',
    why: 'In "Notify" mode every attack in your threat log was allowed through. "Notify and Block" is what actually protects you.',
    caveats: ['IPS inspection reduces maximum throughput on some gateways — check your model\'s IPS throughput rating.'],
    params: [
      {
        key: 'mode',
        label: 'Mode',
        type: 'select',
        default: 'ips',
        options: [
          { value: 'ips', label: 'Notify and Block (IPS)' },
          { value: 'ids', label: 'Notify (IDS, detect only)' },
        ],
      },
    ],
  },
  {
    id: 'disable-upnp',
    title: 'Disable UPnP',
    category: 'exposure',
    icon: 'plug',
    kind: 'setting',
    summary: 'Stop devices from opening ports in your firewall on their own.',
    description: 'Turns off UPnP / NAT-PMP on the gateway, so only port forwards you create yourself are exposed.',
    why: 'UPnP lets any device on your network — including malware — punch holes in your firewall without asking. Exposed ports created this way are invisible unless you go looking.',
    caveats: ['Some games/consoles may report "strict NAT"; create specific port forwards for them instead.'],
    params: [],
  },
  {
    id: 'guest-wifi-isolation',
    title: 'Isolate clients on guest Wi-Fi',
    category: 'wifi',
    icon: 'wifi',
    kind: 'setting',
    summary: 'Stop devices on the guest Wi-Fi from seeing or attacking each other.',
    description: 'Enables client device isolation (L2 isolation) on Wi-Fi networks used by guests.',
    why: 'Guests bring unmanaged devices. Isolation stops one infected guest phone from attacking the others on the same Wi-Fi.',
    caveats: ['Guests can no longer cast to each other\'s devices on the same SSID.'],
    params: [],
  },
  {
    id: 'port-forward',
    title: 'Fix a risky port forward',
    category: 'exposure',
    icon: 'door-open',
    kind: 'setting',
    summary: 'Disable an exposed port forward, or restrict it to a trusted source address.',
    description: 'Updates the selected port forward: either disables it, or limits which source address may use it.',
    why: 'Each port forward exposes a device to the entire internet. Remote-access services in particular are attacked constantly.',
    caveats: ['Disabling the forward breaks remote access through it — use the UniFi VPN instead.'],
    params: [
      { key: 'portForwardId', label: 'Port forward', type: 'text', required: true },
      {
        key: 'mode',
        label: 'Action',
        type: 'select',
        default: 'disable',
        options: [
          { value: 'disable', label: 'Disable the port forward' },
          { value: 'restrict', label: 'Only allow a specific source address' },
        ],
      },
      { key: 'source', label: 'Allowed source (IP or CIDR)', type: 'ip' },
    ],
    hidden: true,
  },
];

TEMPLATES.push({
  id: 'remove-rule',
  title: 'Remove a rule that has no effect',
  category: 'segmentation',
  icon: 'ban',
  kind: 'firewall',
  summary: 'Delete a duplicate, redundant or disabled rule. Only offered when removing it provably changes nothing.',
  description: 'The rule is compared against the rules evaluated before it. If every packet it matches is already handled the same way (or the rule is disabled), deleting it cannot change what your firewall does.',
  why: 'Duplicate and dead rules make the firewall harder to read and audit, and hide real problems.',
  caveats: ['Undo recreates the rule, but it may land at a different position in the rule order.'],
  params: [{ key: 'ruleId', label: 'Rule', type: 'text', required: true }],
  hidden: true,
});

TEMPLATES.push({
  id: 'create-test-network',
  title: 'Create a test network',
  category: 'segmentation',
  icon: 'flask',
  kind: 'firewall',
  summary: 'An empty VLAN (no Wi-Fi, no devices) to safely try the hardening actions on your real controller.',
  description: 'Creates a network named "SC-Test" with a free VLAN id and a subnet that does not overlap your networks, in its own firewall zone where supported.',
  why: 'Lets you see exactly what each hardening action creates in UniFi before using it on networks your devices depend on.',
  caveats: ['Undo removes the network again (undo any test rules first).'],
  params: [],
  hidden: true,
});

/** Offered on every action that creates or changes firewall rules. */
const LOG_PARAM: TemplateParamSpec = {
  key: 'log',
  label: 'Log matches',
  type: 'boolean',
  default: false,
  help: "Turns on logging in UniFi for the rules this change creates or changes, so every connection they match is logged (UniFi's syslog, for a syslog server or SIEM you send it to). Busy rules can log a lot.",
};
for (const t of TEMPLATES) if (t.kind === 'firewall' && t.id !== 'remove-rule' && t.id !== 'create-test-network') t.params.push(LOG_PARAM);

export function getTemplate(id: string): HardeningTemplate | undefined {
  return TEMPLATES.find((t) => t.id === id);
}

export const RISKY_OUTBOUND: Record<string, { label: string; tcp?: string; udp?: string }> = {
  smtp: { label: 'SMTP', tcp: '25' },
  smb: { label: 'SMB/NetBIOS', tcp: '139,445', udp: '137,138' },
  telnet: { label: 'Telnet', tcp: '23,2323' },
  irc: { label: 'IRC', tcp: '6660-6669,6697' },
  tftp: { label: 'TFTP', udp: '69' },
};
