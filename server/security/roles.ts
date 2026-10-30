// Network roles drive the recommendations ("IoT should not reach Trusted"). They are
// inferred from the network name/purpose and can be overridden from the UI.

import { NETWORK_ROLES, type NetworkRole } from '../../shared/types.ts';

const RULES: [RegExp, NetworkRole][] = [
  [/guest|visitor|hotspot|public|gast|invit/i, 'guest'],
  [/cam|cctv|nvr|protect|surveil|doorbell|security ?cam/i, 'cameras'],
  [/iot|smart|things|automation|home ?assistant|zigbee|hue|alexa|sensor|appliance|matter|thread|plug/i, 'iot'],
  [/mgmt|manage|management|infra|network ?gear|admin|oob/i, 'management'],
  [/iscsi|\bsan\b|storage|\bnfs\b|ceph|vsan/i, 'storage'],
  [/server|srv|nas|homelab|services|docker|k8s|cluster/i, 'servers'],
  [/dmz|exposed|internet.?facing|perimeter|untrust/i, 'dmz'],
  [/\blab\b|test|dev\b|sandbox|staging|experiment/i, 'lab'],
  [/voip|voice|phone|sip|pbx|telephon/i, 'voip'],
  [/media|\btv\b|stream|entertain|console|gaming|game|sonos|\bav\b/i, 'media'],
  [/kid|child|family|school|teen/i, 'kids'],
  [/vpn|wireguard|teleport|openvpn|l2tp|tailscale/i, 'vpn'],
  // Whole words only: "VLAN 20" or "Printer network" must not read as "lan" / "work".
  [/\b(default|main|lan|home|trusted|office|corp|private|primary|personal|work|staff|users?)\b/i, 'trusted'],
];

export function inferRole(name: string, purpose: string, isGuest = false): NetworkRole {
  if (isGuest || purpose === 'guest') return 'guest';
  if (/vpn/i.test(purpose)) return 'vpn';
  for (const [re, role] of RULES) if (re.test(name)) return role;
  return 'other';
}

export function trustOf(role: NetworkRole | null | undefined): number {
  return NETWORK_ROLES.find((r) => r.value === role)?.trust ?? 2;
}

export function isUntrusted(role: NetworkRole): boolean {
  return role === 'guest' || role === 'iot' || role === 'cameras' || role === 'dmz';
}

/** Networks whose devices have no business reaching the gateway's admin login: untrusted ones, labs and storage. */
export function keepOffGatewayAdmin(role: NetworkRole): boolean {
  return isUntrusted(role) || role === 'lab' || role === 'storage';
}

/**
 * What we would expect between two networks, given their roles.
 * 'block' = a good segmentation design prevents new connections here.
 */
export function expectedReach(from: NetworkRole, to: NetworkRole): { expected: 'allow' | 'block' | 'either'; reason: string } {
  if (from === 'guest') return { expected: 'block', reason: 'Guest devices should only get internet access.' };
  if (to === 'guest') return { expected: 'either', reason: 'Reaching into the guest network is uncommon but low risk.' };
  if (to === 'management' && from !== 'management' && from !== 'trusted' && from !== 'vpn')
    return { expected: 'block', reason: 'Only trusted/admin devices should reach network management.' };
  if (to === 'storage' && !['trusted', 'management', 'servers', 'vpn', 'storage'].includes(from))
    return { expected: 'block', reason: 'Storage networks carry raw disk traffic; only the servers that use them (and your admin devices) should reach them.' };
  if (from === 'storage' && !['servers', 'management', 'storage'].includes(to))
    return { expected: 'block', reason: 'Storage devices only answer requests from your servers; they have no reason to start connections to other networks.' };
  if (from === 'dmz' && to !== 'dmz')
    return { expected: 'block', reason: 'DMZ servers can be reached from the internet, so assume one may be compromised: it should not start connections into your other networks. Allow only the specific exceptions you need.' };
  if ((from === 'iot' || from === 'cameras') && (to === 'trusted' || to === 'servers' || to === 'management' || to === 'kids' || to === 'vpn'))
    return { expected: 'block', reason: `${label(from)} devices are frequently vulnerable; they should not be able to start connections to ${label(to)} devices.` };
  if (from === 'lab' && (to === 'trusted' || to === 'servers' || to === 'kids'))
    return { expected: 'either', reason: 'Lab machines are experimental; consider keeping them away from your own devices unless you need the access.' };
  if ((from === 'media' || from === 'voip') && (to === 'trusted' || to === 'servers' || to === 'management'))
    return { expected: 'either', reason: `${label(from)} devices usually don't need to start connections to ${label(to)}; consider blocking unless something depends on it.` };
  if (from === 'iot' && to === 'cameras') return { expected: 'block', reason: 'IoT devices have no reason to reach cameras.' };
  if (from === 'cameras' && to === 'iot') return { expected: 'block', reason: 'Cameras have no reason to reach IoT devices.' };
  return { expected: 'either', reason: 'Depends on your needs.' };
}

export function label(role: NetworkRole): string {
  return NETWORK_ROLES.find((r) => r.value === role)?.label ?? role;
}
