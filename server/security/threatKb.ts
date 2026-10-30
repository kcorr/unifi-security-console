// Threat knowledge base: turns raw IDS/IPS signatures into plain-English explanations.
//
// UniFi's IPS is Suricata running Proofpoint Emerging Threats (ET) rules (plus UniFi's own
// lists). ET signatures are named "<RULESET> <CATEGORY> <description>", e.g.
// "ET SCAN Suspicious inbound to mySQL port 3306", so the category token is the most
// reliable classifier. UniFi also attaches its own category name ("catname") and Suricata
// classtype, which we use as fallbacks.

import type { Severity, ThreatCategory, ThreatDirection, ThreatFamily } from '../../shared/types.ts';

export const THREAT_CATEGORIES: Record<string, ThreatCategory> = {
  scan: {
    key: 'scan',
    name: 'Scanning & reconnaissance',
    family: 'recon',
    defaultSeverity: 'low',
    summary: 'Someone is mapping which devices and ports on your network answer.',
    description:
      'A scanner sends probes to many addresses or ports to discover what is reachable — open ports, running services and their versions. Internet-wide scanning is constant: every public IP receives thousands of probes a day from research projects (Shodan, Censys) and from criminals building target lists.',
    whyItMatters:
      'Scanning itself does no damage, but it is the first step of most attacks. Anything a scanner finds open (a port forward, an exposed admin page) is likely to be attacked next.',
    inbound:
      'An outside host probed your public IP. This is background noise for most networks. It only matters if the probed port is actually forwarded to a device.',
    outbound:
      'A device on YOUR network is scanning the internet. That is unusual for normal devices and often means it is infected and recruited into a botnet.',
    internal:
      'One of your devices is scanning other internal devices. This is how infected machines look for their next victim (lateral movement) — investigate the source device unless it is a known network tool.',
    falsePositives: 'Network inventory tools, vulnerability scanners you run yourself, some smart-home hubs and NAS discovery features.',
    recommendations: [
      'Make sure nothing is exposed that does not need to be (review port forwards and UPnP).',
      'Repeated scanning from one source can be blocked outright with an IP block rule.',
      'If the scanner is inside your network, identify the device and check it for malware.',
    ],
    mitre: [{ id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' }, { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' }],
  },
  bruteforce: {
    key: 'bruteforce',
    name: 'Login brute-force',
    family: 'credential',
    defaultSeverity: 'medium',
    summary: 'Repeated attempts to guess a username and password on a remote-access service.',
    description:
      'Automated tools try thousands of common username/password combinations against services such as SSH, RDP, Telnet, VNC, FTP or web logins. IoT botnets (Mirai and its descendants) spread almost entirely this way, using factory-default passwords.',
    whyItMatters:
      'One weak or default password is enough to give an attacker full control of the device. Remote-access services exposed to the internet are attacked within minutes of going online.',
    inbound: 'Someone on the internet is trying to log in to one of your exposed services. Check whether that port really needs to be reachable from the internet.',
    outbound: 'A device on your network is trying to log in to other systems on the internet — a strong sign it is compromised and part of a botnet.',
    internal: 'A device is trying passwords against other devices on your network. Treat the source as compromised until proven otherwise.',
    recommendations: [
      'Do not expose SSH/RDP/Telnet/VNC directly to the internet — use the UniFi VPN (WireGuard/Teleport) instead.',
      'If a service must stay exposed, restrict the port forward to known source IPs and use strong, unique passwords or keys.',
      'Block the attacking IP if it is persistent.',
    ],
    mitre: [{ id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' }],
  },
  reputation: {
    key: 'reputation',
    name: 'Known malicious IP (threat intelligence)',
    family: 'reputation',
    defaultSeverity: 'medium',
    summary: 'Traffic to or from an address on a curated blocklist of attackers or hijacked networks.',
    description:
      'Threat-intelligence lists track addresses with a bad track record: Spamhaus DROP (netblocks hijacked or run by criminals), DShield (top attacking IPs reported by sensors worldwide), CINS Army (IPs with poor reputation in Sentinel IPS), "Compromised Hosts" and similar lists. The signature fires purely because of WHO the other side is, not because of what the traffic contained.',
    whyItMatters:
      'There is rarely a legitimate reason to talk to these addresses. Inbound hits are usually scanning/attacks from known-bad infrastructure; outbound hits can mean a device is contacting criminal infrastructure.',
    inbound: 'A known-bad address tried to reach you. If the IPS blocked it, no action is needed.',
    outbound: 'One of your devices connected TO a known-bad address. Find out which program on that device made the connection — it may be malware, adware or a compromised app.',
    internal: 'Unexpected — reputation lists only contain public addresses. Check for NAT or VPN effects.',
    recommendations: [
      'Keep IPS in "Notify and Block" mode so reputation hits are dropped automatically.',
      'For outbound hits, investigate the internal device that initiated the connection.',
    ],
  },
  tor: {
    key: 'tor',
    name: 'Tor anonymity network',
    family: 'anonymizer',
    defaultSeverity: 'low',
    summary: 'Traffic to or from the Tor anonymity network.',
    description:
      'Tor relays traffic through volunteer servers to hide who is talking to whom. Exit nodes are where Tor traffic re-enters the normal internet, so connections from them could be from anyone.',
    whyItMatters:
      'Inbound Tor traffic is anonymous by design — attackers use it to hide their origin. Outbound Tor traffic from devices that should not use Tor can indicate malware (some families use Tor for command-and-control) or someone bypassing your filtering.',
    inbound: 'A connection came from a Tor exit node. Anonymous inbound traffic to a home or small-business network is almost never legitimate.',
    outbound: 'A device on your network is talking to the Tor network. Confirm whether someone is intentionally using the Tor Browser.',
    internal: 'Not expected for internal traffic.',
    recommendations: ['Block inbound traffic from Tor if you host services.', 'If Tor use is not expected, find out which device and application is responsible.'],
    mitre: [{ id: 'T1090.003', name: 'Multi-hop Proxy', tactic: 'Command and Control' }],
  },
  exploit: {
    key: 'exploit',
    name: 'Exploit attempt',
    family: 'exploit',
    defaultSeverity: 'high',
    summary: 'An attempt to abuse a specific software vulnerability to take over a device or service.',
    description:
      'Exploit signatures match the exact traffic pattern used to trigger a known vulnerability (often identified by a CVE number) — for example Log4Shell, router command injections, or VPN/firewall appliance bugs. Attackers spray these at every reachable IP, hoping to find unpatched systems.',
    whyItMatters:
      'If the targeted software is running and unpatched, a single successful exploit can give the attacker full remote control. Even blocked attempts tell you what attackers are looking for.',
    inbound: 'Someone tried to exploit a vulnerability through your public IP. It is only dangerous if the targeted product is reachable (port forward / exposed service) and unpatched.',
    outbound: 'A device on your network is SENDING exploit attempts — it is very likely compromised and attacking others.',
    internal: 'Exploit traffic between internal devices is a strong indicator of an active intrusion spreading through your network.',
    recommendations: [
      'Check whether the product named in the signature exists on your network, and patch it.',
      'Close port forwards that are not strictly necessary.',
      'Make sure IPS runs in "Notify and Block" mode so exploit traffic is dropped.',
    ],
    mitre: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
  },
  'web-attack': {
    key: 'web-attack',
    name: 'Web application attack',
    family: 'web',
    defaultSeverity: 'medium',
    summary: 'Malicious requests against a web server or web application (SQL injection, path traversal, remote code execution…).',
    description:
      'These signatures inspect HTTP requests for attack patterns: SQL injection, directory traversal (../../etc/passwd), command injection, attempts to reach admin panels or known-vulnerable scripts (WordPress plugins, PHPUnit, ThinkPHP, etc.).',
    whyItMatters:
      'Only relevant if you host a website, NAS web interface, camera, or other HTTP service that is reachable from the internet. Successful web attacks can leak data or give attackers code execution.',
    inbound: 'Someone is attacking a web service via your public IP. If you do not host any web service, the attack hits nothing.',
    outbound: 'A device on your network is attacking web servers elsewhere — likely compromised.',
    internal: 'Web attack traffic inside your network suggests a compromised device probing internal web interfaces (routers, NAS, cameras).',
    recommendations: [
      'Do not expose web admin interfaces (NAS, cameras, routers) via port forwards.',
      'Keep any self-hosted web apps patched, or put them behind a VPN / reverse proxy with authentication.',
    ],
    mitre: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
  },
  'client-side': {
    key: 'client-side',
    name: 'Drive-by / client-side attack',
    family: 'exploit',
    defaultSeverity: 'high',
    summary: 'Malicious content delivered to a browser or app on one of your devices.',
    description:
      'Exploit kits and malicious web content try to compromise the device that downloads them (browser, document reader, media player). These signatures inspect what your devices download from the internet.',
    whyItMatters: 'A successful client-side exploit installs malware without the user doing anything beyond visiting a page.',
    inbound: 'Malicious content was sent to one of your devices in response to a web request it made.',
    outbound: 'One of your devices requested content associated with an exploit kit.',
    internal: 'Unusual inside a network; check the source device.',
    recommendations: ['Make sure the affected device and its browser are fully updated.', 'Run a malware scan on the device that received the content.'],
    mitre: [{ id: 'T1189', name: 'Drive-by Compromise', tactic: 'Initial Access' }],
  },
  malware: {
    key: 'malware',
    name: 'Malware / command-and-control',
    family: 'malware',
    defaultSeverity: 'critical',
    summary: 'Traffic that matches known malware: an infected device phoning home, downloading payloads, or exfiltrating data.',
    description:
      'Malware signatures (formerly "ET TROJAN") match the network behaviour of specific malware families — check-ins to command-and-control (C2) servers, beacons, payload downloads, stolen-data uploads. Many identify the malware family by name.',
    whyItMatters:
      'An outbound malware hit is one of the most important alerts you can get: it usually means a device on your network is already infected and under someone else\'s control.',
    inbound: 'Malware-related traffic arrived from outside — e.g. a malicious download. Check the receiving device.',
    outbound: 'A device on YOUR network is behaving like infected malware. Isolate it from the network and scan or reinstall it.',
    internal: 'Malware traffic between internal devices suggests it is spreading. Isolate the source device immediately.',
    recommendations: [
      'Identify the device (click the internal IP) and disconnect or quarantine it.',
      'Scan it with up-to-date anti-malware, or reinstall it if it is an IoT device that cannot be scanned.',
      'Change passwords that were used on that device.',
      'Keep IPS in "Notify and Block" mode so known C2 traffic is cut off.',
    ],
    mitre: [{ id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' }],
  },
  botnet: {
    key: 'botnet',
    name: 'Botnet command server',
    family: 'malware',
    defaultSeverity: 'high',
    summary: 'Communication with a known botnet command-and-control server.',
    description:
      'Botnets are networks of infected devices controlled from central "C&C" servers. These signatures fire when traffic goes to or from addresses known to host such servers.',
    whyItMatters: 'Talking to a botnet controller means a device is (or is about to be) taking orders from criminals: sending spam, joining DDoS attacks, or scanning others.',
    inbound: 'A known botnet controller contacted you — usually probing for new victims.',
    outbound: 'A device on your network contacted a botnet controller. Treat it as infected.',
    internal: 'Not expected for internal traffic.',
    recommendations: ['Find the internal device responsible and isolate it.', 'Block the controller IP (the IPS does this automatically in "Notify and Block" mode).'],
    mitre: [{ id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control' }],
  },
  'attack-response': {
    key: 'attack-response',
    name: 'Attack response (possible compromise)',
    family: 'malware',
    defaultSeverity: 'critical',
    summary: 'Traffic that typically appears AFTER a successful attack — e.g. command output or a shell being returned.',
    description:
      'Attack-response signatures look for the tell-tale results of a successful intrusion: output of commands like "id" returning root, directory listings, reverse shells, or error pages leaking data.',
    whyItMatters: 'This is evidence of success, not just an attempt. A device may have been taken over.',
    inbound: 'A remote system returned data that looks like the result of a successful attack — check what your device was talking to.',
    outbound: 'One of your devices sent data that looks like the output of a hijacked shell. Investigate it urgently.',
    internal: 'Possible compromise between internal devices. Investigate both ends.',
    recommendations: ['Isolate the internal device involved and investigate it.', 'Check the logs of the targeted service for unknown logins or commands.'],
    mitre: [{ id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' }],
  },
  phishing: {
    key: 'phishing',
    name: 'Phishing',
    family: 'malware',
    defaultSeverity: 'high',
    summary: 'A device loaded a page or sent data matching a known phishing kit.',
    description: 'Phishing signatures match fake login pages and credential-harvesting kits, and the submission of credentials to them.',
    whyItMatters: 'If someone typed a password into the page, that account should be considered compromised.',
    inbound: 'A phishing page was delivered to one of your devices.',
    outbound: 'A device on your network submitted data to a phishing site — a password may have been stolen.',
    internal: 'Unusual inside a network.',
    recommendations: ['Ask the user of that device what site they visited.', 'Change any password that may have been entered and enable MFA on that account.'],
    mitre: [{ id: 'T1566', name: 'Phishing', tactic: 'Initial Access' }],
  },
  coinmining: {
    key: 'coinmining',
    name: 'Cryptocurrency mining',
    family: 'malware',
    defaultSeverity: 'medium',
    summary: 'A device is talking to a cryptocurrency mining pool.',
    description: 'Mining software connects to "pools" using the Stratum protocol. Unauthorized miners (cryptojacking) are a common payload for compromised servers, NAS devices and browsers.',
    whyItMatters: 'Hidden mining burns electricity, slows the device and is usually a symptom of a wider compromise.',
    inbound: 'Mining-related traffic from outside — often harmless noise.',
    outbound: 'A device on your network is mining (or trying to). If nobody intentionally runs a miner, it is likely compromised.',
    internal: 'Mining traffic between internal devices — check both.',
    recommendations: ['Identify the device and check for unknown processes or containers.', 'Block mining pools if mining is not wanted on your network.'],
    mitre: [{ id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' }],
  },
  dos: {
    key: 'dos',
    name: 'Denial of service',
    family: 'dos',
    defaultSeverity: 'medium',
    summary: 'Traffic patterns intended to overload a device or service.',
    description: 'Denial-of-service signatures detect floods and packets crafted to crash or exhaust a service (e.g. amplification probes, SYN floods, malformed packets).',
    whyItMatters: 'Can knock services or your internet connection offline. Outbound DoS means your devices are being used to attack others.',
    inbound: 'Your public IP received traffic consistent with a denial-of-service attempt or amplification probe.',
    outbound: 'A device on your network is participating in a denial-of-service attack (often an infected IoT device).',
    internal: 'Floods inside your network can come from a misbehaving or compromised device.',
    recommendations: ['Check for exposed UDP services (DNS, NTP, SSDP, memcached) that can be abused for amplification.', 'Identify and isolate internal sources.'],
    mitre: [{ id: 'T1498', name: 'Network Denial of Service', tactic: 'Impact' }],
  },
  dns: {
    key: 'dns',
    name: 'Suspicious DNS activity',
    family: 'policy',
    defaultSeverity: 'low',
    summary: 'DNS lookups for suspicious domains, unusual TLDs, dynamic DNS or DNS tunneling patterns.',
    description: 'DNS signatures look at the names devices try to resolve: dynamic-DNS providers, newly-registered or abused top-level domains, very long encoded names (DNS tunneling) or known-bad domains.',
    whyItMatters: 'Malware has to find its servers somehow; DNS is usually how. Many hits are benign, but they are cheap early-warning signals.',
    inbound: 'Unusual DNS traffic from outside — possibly someone abusing an exposed DNS server.',
    outbound: 'A device looked up a suspicious name. Usually low risk on its own; correlate with other alerts for the same device.',
    internal: 'Suspicious lookups seen inside the network.',
    recommendations: ['Force all devices to use your gateway / filtering DNS (see the "Block external DNS" hardening action).', 'Investigate devices with repeated hits.'],
    mitre: [{ id: 'T1071.004', name: 'DNS', tactic: 'Command and Control' }],
  },
  voip: {
    key: 'voip',
    name: 'VoIP / SIP scanning',
    family: 'recon',
    defaultSeverity: 'low',
    summary: 'Probing for VoIP phone systems (SIP), usually to commit toll fraud.',
    description: 'Tools like SIPVicious ("friendly-scanner") scan for SIP servers and phones and try to register to them, so criminals can route expensive calls through your phone system.',
    whyItMatters: 'Only matters if you expose a PBX or SIP device; then it can cost real money.',
    inbound: 'Someone probed your public IP for SIP services.',
    outbound: 'A device on your network is scanning for SIP services — likely compromised.',
    internal: 'SIP scanning inside your network — check the source.',
    recommendations: ['Never expose SIP (UDP/TCP 5060-5061) to the whole internet; restrict to your VoIP provider\'s IPs.'],
    mitre: [{ id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' }],
  },
  policy: {
    key: 'policy',
    name: 'Policy violation',
    family: 'policy',
    defaultSeverity: 'low',
    summary: 'Traffic that is not necessarily malicious but is risky or against common security policy.',
    description:
      'Policy signatures flag behaviour such as remote-access tools (TeamViewer, AnyDesk), external IP lookups, file-sharing sites, cleartext passwords, outdated software, or scripted user-agents (curl/python) — things an organisation may want to know about.',
    whyItMatters: 'Mostly informational. They become important when they appear on devices that should not do these things, or together with other alerts.',
    inbound: 'Inbound traffic matched a policy rule — usually informational.',
    outbound: 'A device did something that is often fine but sometimes used by malware (e.g. checking its public IP, using a remote-access tool).',
    internal: 'Internal policy event — informational.',
    recommendations: ['Review whether the flagged behaviour is expected for that device.', 'Use IPS suppression for signatures you consider normal on your network.'],
  },
  info: {
    key: 'info',
    name: 'Informational / hunting',
    family: 'info',
    defaultSeverity: 'info',
    summary: 'Low-confidence indicators that are useful context but rarely actionable alone.',
    description: 'INFO and HUNTING signatures describe interesting-but-common behaviour: unusual ports, suspicious file types, rare user agents, connections to file-hosting services. Analysts use them to correlate with stronger alerts.',
    whyItMatters: 'On their own these are usually benign. Look for the same device triggering higher-severity alerts.',
    inbound: 'Informational inbound event.',
    outbound: 'Informational outbound event — check only if the device also has other alerts.',
    internal: 'Informational internal event.',
    recommendations: ['No action needed unless correlated with other alerts.'],
  },
  p2p: {
    key: 'p2p',
    name: 'Peer-to-peer file sharing',
    family: 'policy',
    defaultSeverity: 'low',
    summary: 'BitTorrent or other peer-to-peer protocols.',
    description: 'P2P signatures detect BitTorrent, DHT and similar protocols. P2P clients exchange traffic with thousands of unknown peers.',
    whyItMatters: 'Can expose your IP to copyright notices, malware-laden downloads and heavy bandwidth use. Unexpected P2P on IoT devices can be botnet traffic (some botnets use P2P).',
    inbound: 'Peers on the internet are connecting to a P2P client on your network.',
    outbound: 'A device on your network is using peer-to-peer file sharing.',
    internal: 'Local P2P traffic.',
    recommendations: ['If P2P is not allowed, block it with an app-based traffic rule for the relevant networks.'],
  },
  pup: {
    key: 'pup',
    name: 'Adware / unwanted software',
    family: 'malware',
    defaultSeverity: 'low',
    summary: 'Traffic from adware, toolbars or other potentially unwanted programs (PUPs).',
    description: 'PUPs are not quite malware, but they track users, inject ads and frequently bundle worse software.',
    whyItMatters: 'Low direct risk, but indicates sloppy software installs on that device.',
    inbound: 'Adware-related content delivered to a device.',
    outbound: 'A device is running adware or an unwanted program.',
    internal: 'Unusual internally.',
    recommendations: ['Uninstall unknown programs/browser extensions on the device.'],
  },
  anomaly: {
    key: 'anomaly',
    name: 'Protocol anomaly',
    family: 'protocol',
    defaultSeverity: 'info',
    summary: 'Malformed or unusual packets detected by Suricata\'s protocol decoders.',
    description: 'Signatures starting with "SURICATA" come from the engine itself: out-of-window TCP packets, invalid TLS handshakes, HTTP protocol violations. Flaky connections and some legitimate apps trigger them.',
    whyItMatters: 'Rarely an attack by itself; mostly noise. Very high volumes can point at evasion attempts or broken devices.',
    inbound: 'Malformed inbound traffic — usually noise.',
    outbound: 'Malformed traffic from a device — usually a buggy app or connection issue.',
    internal: 'Malformed internal traffic — usually noise.',
    recommendations: ['Safe to ignore unless volume is very high; consider suppressing noisy signatures.'],
  },
  'remote-access': {
    key: 'remote-access',
    name: 'Remote access service probe',
    family: 'recon',
    defaultSeverity: 'medium',
    summary: 'Probes and connection attempts against remote-administration services (RDP, VNC, Telnet, SSH, SMB).',
    description: 'Remote-access services are the most attacked services on the internet because they give an attacker direct control when they get in.',
    whyItMatters: 'If any of these services is port-forwarded, expect constant password-guessing and exploit attempts against it.',
    inbound: 'Someone probed a remote-access service via your public IP.',
    outbound: 'A device on your network is probing remote-access services on the internet — likely compromised.',
    internal: 'A device is probing remote-access services inside your network.',
    recommendations: ['Use a VPN instead of exposing remote-access services.', 'Restrict any necessary port forward to known source IPs.'],
    mitre: [{ id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access' }],
  },
  inappropriate: {
    key: 'inappropriate',
    name: 'Inappropriate content',
    family: 'policy',
    defaultSeverity: 'info',
    summary: 'Access to adult, gambling or similar content categories.',
    description: 'Content-category signatures flag access to sites that many networks prefer to block.',
    whyItMatters: 'A content/acceptable-use concern rather than a security threat, though such sites carry higher malware risk.',
    inbound: 'Inappropriate content was delivered to a device.',
    outbound: 'A device accessed content in an inappropriate category.',
    internal: '—',
    recommendations: ['Use UniFi content filtering on the networks where this is not allowed.'],
  },
  apps: {
    key: 'apps',
    name: 'Games / chat applications',
    family: 'policy',
    defaultSeverity: 'info',
    summary: 'Traffic from gaming platforms or chat applications.',
    description: 'Application signatures identify specific games and chat apps.',
    whyItMatters: 'Not a threat; useful for acceptable-use policies.',
    inbound: 'Game/chat related traffic.',
    outbound: 'A device is using a game or chat app.',
    internal: '—',
    recommendations: ['No action needed unless this application is not allowed on that network.'],
  },
  ics: {
    key: 'ics',
    name: 'Industrial control (SCADA) protocols',
    family: 'protocol',
    defaultSeverity: 'medium',
    summary: 'Traffic using industrial protocols such as Modbus, DNP3 or BACnet.',
    description: 'Industrial and building-automation protocols have little or no security. Seeing them across the internet boundary is unusual.',
    whyItMatters: 'Exposed industrial or building-control systems can be manipulated without authentication.',
    inbound: 'Someone probed for industrial-control services.',
    outbound: 'A device spoke an industrial protocol to the internet.',
    internal: 'Industrial protocol traffic inside the network.',
    recommendations: ['Never expose these protocols to the internet; isolate such devices on their own VLAN.'],
  },
  honeypot: {
    key: 'honeypot',
    name: 'Internal honeypot triggered',
    family: 'recon',
    defaultSeverity: 'high',
    summary: 'A device on your network touched the UniFi honeypot address — nothing legitimate should ever do that.',
    description: 'The UniFi internal honeypot is a decoy IP that no legitimate service uses. Any connection to it means a device is scanning or probing the local network.',
    whyItMatters: 'Internal scanning is classic behaviour of malware looking to spread (worms, ransomware) or of a compromised IoT device.',
    inbound: '—',
    outbound: '—',
    internal: 'The source device is probing your network. Identify it and check it for compromise.',
    recommendations: ['Identify the source device and isolate it if you do not recognise the behaviour.'],
    mitre: [{ id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' }],
  },
  'tls-fingerprint': {
    key: 'tls-fingerprint',
    name: 'Suspicious TLS fingerprint',
    family: 'malware',
    defaultSeverity: 'medium',
    summary: 'The way a device set up an encrypted (TLS) connection matches a fingerprint (JA3/JA4) associated with malware or hacking tools.',
    description: 'Even though TLS traffic is encrypted, the handshake reveals a fingerprint of the client software. Some fingerprints are strongly associated with malware families or offensive tools.',
    whyItMatters: 'Medium-confidence indicator of malicious software on the device; fingerprints can collide with legitimate software.',
    inbound: 'A remote client with a suspicious fingerprint connected to you.',
    outbound: 'A program on one of your devices uses a TLS fingerprint associated with malware.',
    internal: 'Suspicious fingerprint between internal devices.',
    recommendations: ['Correlate with other alerts for the same device.'],
    mitre: [{ id: 'T1573', name: 'Encrypted Channel', tactic: 'Command and Control' }],
  },
  'geo-block': {
    key: 'geo-block',
    name: 'Region / country block',
    family: 'reputation',
    defaultSeverity: 'info',
    summary: 'Traffic stopped because of a region (country) blocking rule.',
    description: 'Region blocking drops traffic to or from countries you selected, based on IP geolocation.',
    whyItMatters: 'Reduces noise from regions you never communicate with. Geolocation is approximate and attackers can use servers anywhere.',
    inbound: 'Inbound traffic from a blocked region was dropped.',
    outbound: 'A device tried to reach a blocked region.',
    internal: '—',
    recommendations: ['No action needed — this is your region block working.'],
  },
  unknown: {
    key: 'unknown',
    name: 'Other / unclassified',
    family: 'other',
    defaultSeverity: 'low',
    summary: 'A detection that does not fit a known category.',
    description: 'The signature could not be mapped to a known category. Check the signature text and ID for details.',
    whyItMatters: 'Unknown — use the signature name and the involved devices to judge.',
    inbound: 'Inbound detection.',
    outbound: 'Outbound detection from one of your devices.',
    internal: 'Internal detection.',
    recommendations: ['Search the signature ID online (e.g. "ET sid <id>") for details.'],
  },
};

// ET/GPL category token → our category key.
const ET_CATEGORY_MAP: Record<string, string> = {
  SCAN: 'scan',
  ICMP: 'scan',
  ICMP_INFO: 'scan',
  DROP: 'reputation',
  DSHIELD: 'reputation',
  CINS: 'reputation',
  COMPROMISED: 'reputation',
  '3CORESEC': 'reputation',
  CIARMY: 'reputation',
  BOTCC: 'botnet',
  TOR: 'tor',
  EXPLOIT: 'exploit',
  SHELLCODE: 'exploit',
  EXPLOIT_KIT: 'client-side',
  WEB_CLIENT: 'client-side',
  ACTIVEX: 'client-side',
  WEB_SERVER: 'web-attack',
  WEB_SPECIFIC_APPS: 'web-attack',
  SQL: 'web-attack',
  MALWARE: 'malware',
  TROJAN: 'malware',
  MOBILE_MALWARE: 'malware',
  WORM: 'malware',
  VIRUS: 'malware',
  ATTACK_RESPONSE: 'attack-response',
  PHISHING: 'phishing',
  COINMINING: 'coinmining',
  DOS: 'dos',
  DDOS: 'dos',
  DNS: 'dns',
  VOIP: 'voip',
  POLICY: 'policy',
  USER_AGENTS: 'policy',
  INFO: 'info',
  HUNTING: 'info',
  DELETED: 'info',
  CURRENT_EVENTS: 'malware',
  P2P: 'p2p',
  ADWARE_PUP: 'pup',
  INAPPROPRIATE: 'inappropriate',
  GAMES: 'apps',
  CHAT: 'apps',
  SCADA: 'ics',
  SCADA_SPECIAL: 'ics',
  JA3: 'tls-fingerprint',
  TELNET: 'remote-access',
  NETBIOS: 'remote-access',
  RPC: 'remote-access',
  FTP: 'remote-access',
  SNMP: 'scan',
  TFTP: 'remote-access',
  SMTP: 'policy',
  IMAP: 'policy',
  POP3: 'policy',
  MISC: 'unknown',
};

// Fallback by UniFi "catname" / Suricata classtype keywords.
const KEYWORD_MAP: [RegExp, string][] = [
  [/honeypot/i, 'honeypot'],
  [/geo|region|country/i, 'geo-block'],
  [/botcc|botnet/i, 'botnet'],
  [/tor\b/i, 'tor'],
  [/dshield|drop|ciarmy|compromised|reputation|threat.?intel|blocklist|blocker.?list|malicious.?hosts?|dark.?web|threatview|3coresec|spamhaus/i, 'reputation'],
  [/malware|trojan|virus|worm|command and control|c2|ransom/i, 'malware'],
  [/attack.?response|successful/i, 'attack-response'],
  [/phish|social engineering|credential theft/i, 'phishing'],
  [/coin|mining|crypto/i, 'coinmining'],
  [/denial of service|\bdos\b|ddos/i, 'dos'],
  [/brute|login|default username/i, 'bruteforce'],
  [/web application|web.?server|web.?specific|sql/i, 'web-attack'],
  [/exploit|shellcode|privilege gain|executable code/i, 'exploit'],
  [/scan|recon|information leak/i, 'scan'],
  [/p2p|peer/i, 'p2p'],
  [/policy|privacy violation|user.?agent/i, 'policy'],
  [/dns/i, 'dns'],
  [/voip|sip/i, 'voip'],
  [/protocol command decode|non-standard protocol|unusual port|stream|anomal/i, 'anomaly'],
  [/adware|unwanted/i, 'pup'],
  [/inappropriate|adult|gambl/i, 'inappropriate'],
  [/game|chat/i, 'apps'],
  [/info|hunting|misc activity|not suspicious|unknown traffic/i, 'info'],
];

// Specific, well-known signature patterns get a tailored headline.
const NOTABLE: { re: RegExp; category?: string; headline: string; detail?: string }[] = [
  { re: /log4j|CVE-2021-44228|jndi/i, category: 'exploit', headline: 'Log4Shell (Apache Log4j) exploitation attempt', detail: 'Attackers inject a ${jndi:...} string hoping a Java application logs it and downloads attacker code. Still one of the most-sprayed exploits on the internet.' },
  { re: /mirai.*(inbound|scan|user-agent)|(scan|user-agent).*mirai/i, category: 'scan', headline: 'IoT botnet (Mirai) scanning', detail: 'Mirai-style botnets scan the internet for routers, cameras and DVRs with default passwords or known exploits. Inbound probes are noise unless such a device is exposed.' },
  { re: /mirai|gafgyt|mozi/i, category: 'malware', headline: 'IoT botnet (Mirai family) activity', detail: 'Mirai-style botnets infect routers, cameras and DVRs using default passwords and router exploits, then use them for DDoS attacks.' },
  { re: /cobalt ?strike/i, category: 'malware', headline: 'Cobalt Strike beacon', detail: 'Cobalt Strike is a commercial attack framework widely abused by ransomware groups. A beacon is the implant checking in with its operator.' },
  { re: /sipvicious|friendly-scanner/i, category: 'voip', headline: 'SIPVicious VoIP scanner', detail: 'The "friendly-scanner" tool hunts for SIP phone systems to commit toll fraud.' },
  { re: /zmap|masscan/i, category: 'scan', headline: 'Mass internet scanner (ZMap/Masscan)', detail: 'These tools can scan the entire IPv4 internet in minutes. Used by both researchers and attackers.' },
  { re: /nmap/i, category: 'scan', headline: 'Nmap scan', detail: 'Nmap is the most common port-scanning tool.' },
  { re: /spamhaus drop/i, category: 'reputation', headline: 'Spamhaus DROP listed network', detail: 'Spamhaus DROP lists netblocks that are hijacked or operated by professional criminals. No legitimate traffic should come from them.' },
  { re: /dshield/i, category: 'reputation', headline: 'DShield top attacker', detail: 'The source is on the SANS DShield list of the most active attacking IPs worldwide.' },
  { re: /cins active threat/i, category: 'reputation', headline: 'CINS Army poor-reputation IP', detail: 'Listed by CINS Army (Sentinel IPS) for repeated malicious activity seen across many networks.' },
  { re: /compromised or hostile/i, category: 'reputation', headline: 'Known compromised / hostile host', detail: 'The other side is a host known to be compromised or used for attacks.' },
  { re: /tor (exit|relay|known)/i, category: 'tor', headline: 'Tor node traffic' },
  { re: /(ssh|libssh).*(scan|brute)|(scan|brute).*ssh/i, category: 'bruteforce', headline: 'SSH scan / password guessing' },
  { re: /\b(rdp|ms terminal server|3389)\b/i, category: 'remote-access', headline: 'Remote Desktop (RDP) probe', detail: 'RDP is one of the most common ways ransomware operators get in.' },
  { re: /\bvnc\b/i, category: 'remote-access', headline: 'VNC remote-desktop probe' },
  { re: /telnet/i, category: 'remote-access', headline: 'Telnet probe', detail: 'Telnet sends passwords in clear text and is the main way IoT botnets spread.' },
  { re: /\bsmb\b|\bnetbios\b|445/i, category: 'remote-access', headline: 'Windows file sharing (SMB) probe', detail: 'SMB should never be reachable from the internet (WannaCry spread this way).' },
  { re: /(mysql|mssql|ms-sql|postgres|oracle|redis|mongodb|elasticsearch|memcached|couchdb|cassandra)/i, category: 'scan', headline: 'Database service probe', detail: 'Attackers look for databases exposed to the internet, which are frequently unauthenticated.' },
  { re: /possible external ip lookup|ipify|icanhazip|checkip|ipinfo\.io|ip-api/i, category: 'policy', headline: 'Device checked its public IP address', detail: 'Many legitimate apps do this, but so does malware right after infection. Only worth investigating on devices with other alerts.' },
  { re: /dyn(amic)?.?dns|no-ip|duckdns|dyndns/i, category: 'dns', headline: 'Dynamic DNS domain lookup', detail: 'Dynamic DNS is used by home servers — and by malware to locate C2 servers.' },
  { re: /teamviewer|anydesk|rustdesk|screenconnect|connectwise|splashtop/i, category: 'policy', headline: 'Remote-access tool in use', detail: 'Legitimate support tools, but also the #1 tool in tech-support scams. Make sure it is expected.' },
  { re: /bittorrent|utorrent|\bdht\b/i, category: 'p2p', headline: 'BitTorrent traffic' },
  { re: /stratum|xmrig|monero|coinhive|coin ?miner/i, category: 'coinmining', headline: 'Cryptocurrency mining' },
  { re: /eicar/i, category: 'info', headline: 'EICAR test file', detail: 'A harmless anti-virus test file — someone is testing detection.' },
  { re: /gpon|dasan/i, category: 'exploit', headline: 'GPON router exploit', detail: 'An old but still widely-sprayed remote code execution against fibre (GPON) routers.' },
  { re: /hikvision|dahua|\bdvr\b|\bnvr\b|ip ?camera/i, category: 'exploit', headline: 'IP camera / DVR exploit attempt', detail: 'Cameras and DVRs are favourite botnet targets — keep them off the internet and on an isolated VLAN.' },
  { re: /(netgear|d-link|dlink|tp-link|tplink|zyxel|linksys|tenda|totolink|realtek|huawei hg|draytek|mikrotik)/i, category: 'exploit', headline: 'Consumer router / IoT exploit attempt' },
  { re: /(fortinet|fortios|fortigate|citrix|netscaler|pulse secure|ivanti|palo alto|pan-os|sonicwall|f5 big-ip|cisco asa)/i, category: 'exploit', headline: 'VPN / firewall appliance exploit attempt', detail: 'Edge appliances are prime targets for ransomware groups and state actors.' },
  { re: /(confluence|exchange|proxyshell|proxylogon|sharepoint|weblogic|struts|spring4shell|jenkins|moveit|vmware|vcenter)/i, category: 'exploit', headline: 'Enterprise application exploit attempt' },
  { re: /(wordpress|wp-|joomla|drupal|phpunit|thinkphp|laravel|vbulletin|phpmyadmin)/i, category: 'web-attack', headline: 'Web application (CMS / PHP) attack' },
  { re: /(\.\.\/|directory traversal|path traversal|etc\/passwd)/i, category: 'web-attack', headline: 'Path traversal attempt' },
  { re: /sql injection|union select/i, category: 'web-attack', headline: 'SQL injection attempt' },
  { re: /shellshock|bash.*cgi/i, category: 'exploit', headline: 'Shellshock (Bash) exploit attempt' },
  { re: /docker|kubernetes|kubelet/i, category: 'exploit', headline: 'Exposed container API probe' },
  { re: /\bupnp\b|\bssdp\b/i, category: 'scan', headline: 'UPnP / SSDP probe', detail: 'Exposed UPnP/SSDP can leak device info and be abused for DDoS amplification.' },
  { re: /(ntp|memcached|chargen|ssdp|cldap).*(amplif|reflect|monlist)/i, category: 'dos', headline: 'DDoS amplification probe' },
  { re: /suspicious inbound to .* port (\d+)/i, category: 'scan', headline: 'Probe of a sensitive port' },
];

const RULESET_RE = /^\s*(ET|ETPRO|GPL|SURICATA|UBNT|UNIFI|ET-PRO|PT|TGI|CUSTOM)\s+([A-Z0-9_]+)?/i;
const CVE_RE = /CVE[-_ ]?(\d{4})[-_ ](\d{4,7})/gi;

export interface SignatureAnalysis {
  categoryKey: string;
  ruleset: string | null;
  etCategory: string | null;
  headline: string;
  detail: string | null;
  cves: string[];
}

export function analyzeSignature(signature: string, hints: { catname?: string | null; classtype?: string | null } = {}): SignatureAnalysis {
  const sig = (signature || '').trim();
  let categoryKey: string | null = null;
  let ruleset: string | null = null;
  let etCategory: string | null = null;

  const m = RULESET_RE.exec(sig);
  if (m) {
    ruleset = m[1].toUpperCase();
    if (ruleset === 'SURICATA') categoryKey = 'anomaly';
    else if (m[2]) {
      etCategory = m[2].toUpperCase();
      categoryKey = ET_CATEGORY_MAP[etCategory] ?? null;
    }
  }

  const notable = NOTABLE.find((n) => n.re.test(sig));
  // Specific patterns refine generic buckets (e.g. "ET SCAN ... SSH" → brute force), but never
  // override a definite classification such as reputation or malware.
  if (notable?.category) {
    const generic = !categoryKey || categoryKey === 'unknown' || categoryKey === 'info';
    const reconRefine = (categoryKey === 'scan' || categoryKey === 'remote-access') && ['bruteforce', 'remote-access', 'voip', 'scan'].includes(notable.category);
    if (generic || reconRefine) categoryKey = notable.category;
  }

  if (!categoryKey) {
    for (const hint of [hints.catname, hints.classtype]) {
      if (!hint) continue;
      const k = KEYWORD_MAP.find(([re]) => re.test(hint));
      if (k) {
        categoryKey = k[1];
        break;
      }
    }
  }
  if (!categoryKey) {
    const k = KEYWORD_MAP.find(([re]) => re.test(sig));
    categoryKey = k ? k[1] : 'unknown';
  }

  const cves = [...new Set([...sig.matchAll(CVE_RE)].map((x) => `CVE-${x[1]}-${x[2]}`))];
  const category = THREAT_CATEGORIES[categoryKey] ?? THREAT_CATEGORIES.unknown;
  const useNotable = !!notable && (!notable.category || notable.category === category.key);
  let headline = useNotable ? notable!.headline : category.name;
  if (useNotable && /Probe of a sensitive port/.test(notable!.headline)) {
    const port = /port (\d+)/i.exec(sig)?.[1];
    if (port) headline = `Probe of ${portName(Number(port))} (port ${port})`;
  }
  return { categoryKey: category.key, ruleset, etCategory, headline, detail: useNotable ? notable!.detail ?? null : null, cves };
}

const WELL_KNOWN_PORTS: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPCbind', 123: 'NTP', 135: 'MS-RPC', 137: 'NetBIOS', 139: 'NetBIOS/SMB',
  143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IKE/IPsec', 502: 'Modbus', 554: 'RTSP (cameras)', 587: 'SMTP submission',
  631: 'IPP printing', 853: 'DNS-over-TLS', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS proxy', 1194: 'OpenVPN', 1433: 'MS SQL', 1521: 'Oracle DB',
  1723: 'PPTP', 1883: 'MQTT', 1900: 'SSDP/UPnP', 2049: 'NFS', 2323: 'Telnet (alt)', 2375: 'Docker API', 2376: 'Docker API (TLS)', 3128: 'HTTP proxy',
  3306: 'MySQL', 3389: 'RDP', 3478: 'STUN', 4443: 'HTTPS (alt)', 5000: 'UPnP / NAS web', 5060: 'SIP', 5061: 'SIP-TLS', 5353: 'mDNS', 5432: 'PostgreSQL',
  5555: 'Android ADB', 5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 6443: 'Kubernetes API', 7547: 'TR-069 (ISP router mgmt)', 8000: 'HTTP (alt)',
  8080: 'HTTP proxy/alt', 8081: 'HTTP (alt)', 8443: 'HTTPS (alt)', 8888: 'HTTP (alt)', 9000: 'Portainer/PHP-FPM', 9100: 'Printer (JetDirect)', 9200: 'Elasticsearch',
  10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB', 32400: 'Plex', 37777: 'Dahua DVR', 51820: 'WireGuard',
};

export function portName(port: number | null | undefined): string {
  if (!port) return 'unknown service';
  return WELL_KNOWN_PORTS[port] ?? `port ${port}`;
}

/** Remote-access / dangerous services that should essentially never be internet-exposed. */
export const RISKY_EXPOSED_PORTS: Record<number, { name: string; severity: Severity; why: string }> = {
  21: { name: 'FTP', severity: 'high', why: 'Sends passwords unencrypted and is heavily brute-forced.' },
  22: { name: 'SSH', severity: 'medium', why: 'Constantly brute-forced; only acceptable with key-only authentication and a source restriction.' },
  23: { name: 'Telnet', severity: 'critical', why: 'Unencrypted remote shell; the main infection vector for IoT botnets.' },
  135: { name: 'MS-RPC', severity: 'critical', why: 'Windows RPC should never be exposed to the internet.' },
  139: { name: 'NetBIOS/SMB', severity: 'critical', why: 'Windows file sharing; exploited by worms such as WannaCry.' },
  445: { name: 'SMB', severity: 'critical', why: 'Windows file sharing; exploited by worms such as WannaCry.' },
  1433: { name: 'MS SQL', severity: 'high', why: 'Databases are brute-forced and exploited when exposed.' },
  1521: { name: 'Oracle DB', severity: 'high', why: 'Databases should never be directly internet-facing.' },
  2323: { name: 'Telnet (alt)', severity: 'critical', why: 'Alternative telnet port used by IoT devices — botnet magnet.' },
  2375: { name: 'Docker API', severity: 'critical', why: 'Unauthenticated Docker API = full control of the host.' },
  3306: { name: 'MySQL', severity: 'high', why: 'Databases are brute-forced and exploited when exposed.' },
  3389: { name: 'RDP', severity: 'critical', why: 'Remote Desktop is the #1 ransomware entry point.' },
  5432: { name: 'PostgreSQL', severity: 'high', why: 'Databases should never be directly internet-facing.' },
  5555: { name: 'Android ADB', severity: 'critical', why: 'Unauthenticated debug access to Android devices.' },
  5900: { name: 'VNC', severity: 'critical', why: 'Remote desktop, often with weak or no passwords.' },
  5985: { name: 'WinRM', severity: 'high', why: 'Windows remote management.' },
  6379: { name: 'Redis', severity: 'critical', why: 'Usually unauthenticated; trivially abused for code execution.' },
  7547: { name: 'TR-069', severity: 'high', why: 'ISP management protocol frequently exploited by botnets.' },
  9200: { name: 'Elasticsearch', severity: 'high', why: 'Frequently exposed without authentication, leaking data.' },
  10000: { name: 'Webmin', severity: 'high', why: 'Server admin panel with a history of critical exploits.' },
  11211: { name: 'Memcached', severity: 'high', why: 'Abused for massive DDoS amplification.' },
  27017: { name: 'MongoDB', severity: 'high', why: 'Commonly exposed without authentication.' },
  37777: { name: 'Dahua DVR', severity: 'high', why: 'Camera/DVR service frequently exploited by botnets.' },
  554: { name: 'RTSP (camera stream)', severity: 'medium', why: 'Camera streams are often unauthenticated.' },
  1900: { name: 'SSDP/UPnP', severity: 'high', why: 'Leaks device info and is used for DDoS amplification.' },
  161: { name: 'SNMP', severity: 'high', why: 'Leaks device configuration; often default community strings.' },
  2049: { name: 'NFS', severity: 'high', why: 'File shares should not be internet-facing.' },
};

const SEV_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function sevRank(s: Severity): number {
  return SEV_ORDER.indexOf(s);
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return sevRank(a) >= sevRank(b) ? a : b;
}

function bump(s: Severity, by: number): Severity {
  return SEV_ORDER[Math.max(0, Math.min(SEV_ORDER.length - 1, sevRank(s) + by))];
}

/**
 * Context-aware severity: Suricata priority (1 = high … 4 = info) combined with what the
 * category means in this direction and whether the IPS actually blocked it.
 */
export function assessSeverity(p: { categoryKey: string; priority?: number | null; direction: ThreatDirection; blocked: boolean | null }): Severity {
  const cat = THREAT_CATEGORIES[p.categoryKey] ?? THREAT_CATEGORIES.unknown;
  let sev: Severity = cat.defaultSeverity;
  if (p.priority) {
    const fromPriority: Severity = p.priority <= 1 ? 'high' : p.priority === 2 ? 'medium' : p.priority === 3 ? 'low' : 'info';
    // Average the two signals, leaning to the category default for noisy families.
    const avg = Math.round((sevRank(sev) + sevRank(fromPriority)) / 2);
    sev = SEV_ORDER[avg];
  }
  const family: ThreatFamily = cat.family;
  if (p.direction === 'outbound' || p.direction === 'internal') {
    // Your own device doing attacker things is far more serious than background noise.
    if (['malware', 'exploit', 'credential', 'web', 'dos'].includes(family)) sev = bump(sev, 2);
    else if (family === 'recon' || family === 'reputation' || family === 'anonymizer') sev = bump(sev, 1);
  } else if (p.direction === 'inbound') {
    if (p.blocked === true && ['recon', 'reputation', 'anonymizer', 'protocol'].includes(family)) sev = bump(sev, -1);
    if (p.blocked === false && ['exploit', 'web', 'credential', 'malware'].includes(family)) sev = bump(sev, 1);
  }
  if (p.categoryKey === 'honeypot') sev = maxSeverity(sev, 'high');
  return sev;
}

export function explainEvent(p: { categoryKey: string; direction: ThreatDirection; blocked: boolean | null }): { meaning: string; action: string } {
  const cat = THREAT_CATEGORIES[p.categoryKey] ?? THREAT_CATEGORIES.unknown;
  const meaning = p.direction === 'outbound' ? cat.outbound : p.direction === 'internal' ? cat.internal : cat.inbound;
  let action: string;
  if (p.direction === 'inbound') {
    action =
      p.blocked === true
        ? 'Blocked by your IPS — no action needed. Block the source permanently if it keeps coming back.'
        : p.blocked === false
          ? 'This traffic was ALLOWED through because the IPS is in "Notify" mode. Switch IPS to "Notify and Block" and close any port forward that is not required.'
          : cat.recommendations[0] ?? 'Review the details.';
  } else if (p.direction === 'outbound') {
    action =
      cat.family === 'policy' || cat.family === 'info' || cat.family === 'protocol'
        ? 'Check that this behaviour is expected for that device.'
        : 'Investigate the internal device that started this connection — it may be compromised.';
  } else if (p.direction === 'internal') {
    action = 'Investigate the source device and consider isolating it on its own VLAN.';
  } else {
    action = cat.recommendations[0] ?? 'Review the details.';
  }
  return { meaning, action };
}

export function listCategories(): ThreatCategory[] {
  return Object.values(THREAT_CATEGORIES);
}
