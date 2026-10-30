// What each rule in a plan will look like in UniFi, field by field: the "detailed view" of a preview.
// Works on the request bodies themselves (official API, internal v2 and legacy), so what is shown is exactly what is sent.

import type { ChangePlan, PlanOperation, RuleDetail, RuleOrder, RuleSide } from '../../../shared/types.ts';
import type { RawSnapshot } from '../../unifi/collect.ts';
import type { FwModel } from '../model.ts';

type Obj = Record<string, unknown>;
/** A rule's fields before it is known whether it is created, changed or removed. */
type Draft = Omit<RuleDetail, 'change' | 'changes'>;
const obj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown) => (typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v));

interface Names {
  zone: (id: string) => string;
  network: (id: string) => string;
  list: (id: string) => string;
  rule: (id: string) => string;
}

function names(model: FwModel, raw: RawSnapshot, plan: ChangePlan): Names {
  // Objects this same plan creates are referred to as "$created:<operation id>".
  const created = (ref: string) => {
    const op = plan.operations.find((o) => `$created:${o.id}` === ref);
    return op ? `${str(obj(op.body).name) || 'new object'} (new)` : null;
  };
  return {
    zone: (id) => created(id) ?? model.zones.find((z) => z.id === id)?.name ?? (id ? 'unknown zone' : 'any zone'),
    network: (id) => created(id) ?? model.networks.find((n) => n.id === id || n.raw._legacyId === id)?.name ?? 'unknown network',
    list: (id) =>
      created(id) ?? str(raw.iLists.find((l) => str(l.id) === id)?.name) ?? str(raw.firewallGroups.find((g) => str(g._id) === id)?.name) ?? 'unknown list',
    rule: (id) => created(id) ?? model.rules.find((r) => r.id === id)?.name ?? 'another rule',
  };
}

const joinPorts = (items: unknown[]) =>
  items
    .map((it) => {
      const i = obj(it);
      return i.type === 'PORT_NUMBER_RANGE' ? `${str(i.start)}–${str(i.stop)}` : str(i.value);
    })
    .filter(Boolean)
    .join(', ');

/** One side of an official-API policy. */
function integrationSide(side: Obj, n: Names, hasPortsOnThisSide: boolean): RuleSide {
  const tf = obj(side.trafficFilter);
  const pf = obj(tf.portFilter);
  const portList = arr(pf.items);
  const ports = hasPortsOnThisSide && portList.length ? `${pf.matchOpposite === true ? 'all except ' : ''}${joinPorts(portList)}` : null;
  let match = 'Any';
  if (tf.type === 'NETWORK') {
    const nf = obj(tf.networkFilter);
    match = `${nf.matchOpposite === true ? 'All networks except ' : 'Networks: '}${arr(nf.networkIds).map((id) => n.network(str(id))).join(', ')}`;
  } else if (tf.type === 'IP_ADDRESS') {
    const ip = obj(tf.ipAddressFilter);
    const not = ip.matchOpposite === true ? 'All addresses except ' : '';
    match =
      ip.type === 'TRAFFIC_MATCHING_LIST'
        ? `${not}${not ? '' : 'IP group: '}“${n.list(str(ip.trafficMatchingListId))}”`
        : `${not || 'IP addresses: '}${arr(ip.items)
            .map((it) => {
              const i = obj(it);
              return i.type === 'IP_ADDRESS_RANGE' ? `${str(i.start)}–${str(i.stop)}` : str(i.value);
            })
            .join(', ')}`;
  } else if (tf.type === 'REGION') {
    match = `Countries: ${arr(obj(tf.regionFilter).regions).map(str).join(', ')}`;
  }
  return { zone: n.zone(str(side.zoneId)), match, ports };
}

function integrationDetail(body: Obj, n: Names): Draft {
  const action = obj(body.action);
  const scope = obj(body.ipProtocolScope);
  const proto = obj(scope.protocolFilter);
  const states = arr(body.connectionStateFilter).map(str);
  return {
    name: str(body.name),
    action: action.type === 'ALLOW' ? 'Allow' : action.type === 'REJECT' ? 'Reject' : 'Block',
    enabled: body.enabled !== false,
    source: integrationSide(obj(body.source), n, true),
    destination: integrationSide(obj(body.destination), n, true),
    protocol: proto.type === 'PRESET' ? (str(obj(proto.preset).name) === 'TCP_UDP' ? 'TCP and UDP' : str(obj(proto.preset).name)) : proto.type === 'NAMED_PROTOCOL' ? str(obj(proto.protocol).name) : 'All',
    ipVersion: scope.ipVersion === 'IPV4' ? 'IPv4 only' : scope.ipVersion === 'IPV6' ? 'IPv6 only' : 'IPv4 and IPv6',
    states: states.length ? stateText(states) : 'All connections',
    logging: body.loggingEnabled === true,
    description: str(body.description) || null,
    position: null,
  };
}

function v2Side(side: Obj, n: Names): RuleSide {
  const target = str(side.matching_target);
  let match = 'Any';
  if (target === 'NETWORK') match = `${side.match_opposite_networks === true ? 'All networks except ' : 'Networks: '}${arr(side.network_ids).map((id) => n.network(str(id))).join(', ')}`;
  else if (target === 'IP')
    match = side.matching_target_type === 'OBJECT' ? `IP group: “${n.list(str(side.ip_group_id))}”` : `${side.match_opposite_ips === true ? 'All addresses except ' : 'IP addresses: '}${arr(side.ips).map(str).join(', ')}`;
  const ports = side.port_matching_type === 'SPECIFIC' && str(side.port) ? `${side.match_opposite_ports === true ? 'all except ' : ''}${str(side.port)}` : null;
  return { zone: n.zone(str(side.zone_id)), match, ports };
}

function v2Detail(body: Obj, n: Names): Draft {
  const protocol = str(body.protocol);
  return {
    name: str(body.name),
    action: body.action === 'ALLOW' ? 'Allow' : body.action === 'REJECT' ? 'Reject' : 'Block',
    enabled: body.enabled !== false,
    source: v2Side(obj(body.source), n),
    destination: v2Side(obj(body.destination), n),
    protocol: protocolText(protocol),
    ipVersion: body.ip_version === 'IPV4' ? 'IPv4 only' : body.ip_version === 'IPV6' ? 'IPv6 only' : 'IPv4 and IPv6',
    states: body.connection_state_type === 'CUSTOM' ? stateText(arr(body.connection_states).map(str)) : 'All connections',
    logging: body.logging === true,
    description: str(body.description) || null,
    position: null,
  };
}

function legacyDetail(body: Obj, n: Names): Draft {
  const side = (prefix: 'src' | 'dst'): RuleSide => {
    const groups = arr(body[`${prefix}_firewallgroup_ids`]).map(str).filter(Boolean);
    const net = str(body[`${prefix}_networkconf_id`]);
    const address = str(body[`${prefix}_address`]);
    const match = groups.length ? `IP group: ${groups.map((g) => `“${n.list(g)}”`).join(', ')}` : net ? `Network: ${n.network(net)}` : address ? `IP address: ${address}` : 'Any';
    const ports = prefix === 'dst' && str(body.dst_port) ? str(body.dst_port) : null;
    return { zone: null, match, ports };
  };
  const states = [body.state_new && 'NEW', body.state_established && 'ESTABLISHED', body.state_related && 'RELATED', body.state_invalid && 'INVALID'].filter(Boolean) as string[];
  return {
    name: str(body.name),
    action: body.action === 'accept' ? 'Allow' : body.action === 'reject' ? 'Reject' : 'Block',
    enabled: body.enabled !== false,
    source: side('src'),
    destination: side('dst'),
    protocol: protocolText(str(body.protocol)),
    ipVersion: 'IPv4 only',
    states: states.length ? stateText(states) : 'All connections',
    logging: body.logging === true,
    description: null,
    position: body.ruleset ? `Rule set ${str(body.ruleset)}, rule index ${str(body.rule_index) || 'next free'}` : null,
  };
}

function protocolText(p: string): string {
  return !p || p === 'all' ? 'All' : p === 'tcp_udp' ? 'TCP and UDP' : p.toUpperCase();
}

function stateText(states: string[]): string {
  const s = new Set(states.map((x) => x.toUpperCase()));
  if (s.size === 2 && s.has('NEW') && s.has('INVALID')) return 'New and invalid only (replies to your own connections still work)';
  return [...s].map((x) => x.charAt(0) + x.slice(1).toLowerCase()).join(', ');
}

function detailOf(body: unknown, path: string, n: Names): Draft | null {
  const b = obj(body);
  if (!b.name && !b.action) return null;
  if (path.includes('/integration/')) return integrationDetail(b, n);
  if (path.includes('/firewall-policies')) return v2Detail(b, n);
  if (path.includes('/rest/firewallrule')) return legacyDetail(b, n);
  return null;
}

const isOrdering = (op: PlanOperation) => /ordering|reorder/.test(op.path);

/** The order an ordering request sets: before/after UniFi's built-in rules, new ones marked. */
function orderOf(op: PlanOperation, n: Names): RuleOrder | null {
  const b = obj(op.body);
  const ids = op.path.includes('/integration/') ? arr(obj(b.orderedFirewallPolicyIds).beforeSystemDefined) : arr(b.before_predefined_ids);
  const q = new URL(op.path, 'http://x').searchParams;
  const src = str(b.source_zone_id) || q.get('sourceFirewallZoneId') || '';
  const dst = str(b.destination_zone_id) || q.get('destinationFirewallZoneId') || '';
  if (!ids.length) return null;
  return { pair: `${n.zone(src)} → ${n.zone(dst)}`, rules: ids.map((id) => ({ name: n.rule(str(id)).replace(/ \(new\)$/, ''), isNew: str(id).startsWith('$created:') })) };
}

/** Field labels for a before/after comparison. */
const FIELDS: [label: string, get: (d: Draft) => string][] = [
  ['Name', (d) => d.name],
  ['Action', (d) => d.action],
  ['Enabled', (d) => (d.enabled ? 'Yes' : 'No')],
  ['Source zone', (d) => d.source.zone ?? '—'],
  ['Source', (d) => d.source.match],
  ['Source ports', (d) => d.source.ports ?? 'Any'],
  ['Destination zone', (d) => d.destination.zone ?? '—'],
  ['Destination', (d) => d.destination.match],
  ['Destination ports', (d) => d.destination.ports ?? 'Any'],
  ['Protocol', (d) => d.protocol],
  ['IP version', (d) => d.ipVersion],
  ['Connections', (d) => d.states],
  ['Logging', (d) => (d.logging ? 'On' : 'Off')],
];

/** Adds the field-by-field view to every firewall rule step of a plan, and the resulting order to ordering steps. */
export function attachRuleDetails(model: FwModel, raw: RawSnapshot, plan: ChangePlan): void {
  const n = names(model, raw, plan);
  const orders = plan.operations.filter(isOrdering).map((op) => ({ op, order: orderOf(op, n) }));
  for (const op of plan.operations) {
    if (op.objectType !== 'firewall-policy' && op.objectType !== 'firewall-rule') continue;
    if (isOrdering(op)) {
      op.order = orders.find((o) => o.op === op)?.order ?? undefined;
      continue;
    }
    if (op.kind === 'delete') {
      const before = detailOf(op.before ?? op.body, op.path, n);
      if (before) op.detail = { ...before, change: 'delete' };
      continue;
    }
    const after = detailOf(op.body, op.path, n);
    if (!after) continue;
    if (op.kind === 'create' && !after.position) {
      // Where the new rule lands: its place in the order this plan sets, else after the rules already in that zone pair.
      const ref = `$created:${op.id}`;
      const placed = orders.find((o) => o.order && o.order.rules.length && JSON.stringify(o.op.body).includes(ref));
      if (placed?.order) {
        const ids = placed.op.path.includes('/integration/') ? arr(obj(obj(placed.op.body).orderedFirewallPolicyIds).beforeSystemDefined) : arr(obj(placed.op.body).before_predefined_ids);
        const i = ids.map(str).indexOf(ref);
        const next = ids[i + 1];
        after.position = `Number ${i + 1} of ${ids.length} in ${placed.order.pair}${next ? `, before “${n.rule(str(next))}”` : ''}`;
      } else {
        after.position = `After your existing rules in ${after.source.zone ?? '?'} → ${after.destination.zone ?? '?'}`;
      }
    }
    op.detail = { ...after, change: op.kind };
    if (op.kind === 'update' && op.before) {
      const before = detailOf(op.before, op.path, n);
      if (before) op.detail.changes = FIELDS.filter(([, get]) => get(before) !== get(after)).map(([field, get]) => ({ field, from: get(before), to: get(after) }));
    }
  }
}
