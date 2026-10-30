// Request bodies for creating/updating firewall rules in each API dialect.

export type Dialect = 'integration' | 'internal-v2' | 'legacy';

export type EndpointSpec =
  | { kind: 'any' }
  | { kind: 'networks'; ids: string[] }
  | { kind: 'ips'; values: string[] }
  | { kind: 'list'; id: string }
  /** ISO country codes; only the official API (Network 10.1+) can match by country. */
  | { kind: 'regions'; codes: string[] };

export interface SvcPart {
  protocol: 'all' | 'tcp' | 'udp' | 'tcp_udp';
  ports: string | null;
}

export interface RuleSpec {
  name: string;
  description: string;
  action: 'BLOCK' | 'ALLOW';
  srcZoneId: string | null;
  dstZoneId: string | null;
  src: EndpointSpec;
  dst: EndpointSpec;
  svc: SvcPart;
  /** 'new' blocks NEW+INVALID connections only (replies keep working); 'all' matches everything. */
  states: 'new' | 'all';
  ipVersion: 'both' | 'v4';
  ruleset?: string;
  ruleIndex?: number;
}

type Obj = Record<string, unknown>;

function integrationPortFilter(ports: string): Obj {
  return {
    type: 'PORTS',
    matchOpposite: false,
    items: ports.split(',').map((p) => {
      const [a, b] = p.trim().split('-').map(Number);
      return b !== undefined && !Number.isNaN(b) ? { type: 'PORT_NUMBER_RANGE', start: a, stop: b } : { type: 'PORT_NUMBER', value: a };
    }),
  };
}

function integrationIpItem(v: string): Obj {
  if (v.includes('-')) {
    const [start, stop] = v.split('-');
    return { type: 'IP_ADDRESS_RANGE', start: start.trim(), stop: stop.trim() };
  }
  return v.includes('/') ? { type: 'SUBNET', value: v } : { type: 'IP_ADDRESS', value: v };
}

function integrationFilter(ep: EndpointSpec, ports: string | null): Obj | undefined {
  const portFilter = ports ? { portFilter: integrationPortFilter(ports) } : {};
  switch (ep.kind) {
    case 'any':
      return ports ? { type: 'PORT', portFilter: integrationPortFilter(ports) } : undefined;
    case 'networks':
      return { type: 'NETWORK', networkFilter: { networkIds: ep.ids, matchOpposite: false }, ...portFilter };
    case 'ips':
      return { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: ep.values.map(integrationIpItem) }, ...portFilter };
    case 'list':
      return { type: 'IP_ADDRESS', ipAddressFilter: { type: 'TRAFFIC_MATCHING_LIST', matchOpposite: false, trafficMatchingListId: ep.id }, ...portFilter };
    case 'regions':
      return { type: 'REGION', regionFilter: { regions: ep.codes }, ...portFilter };
  }
}

export function integrationProtocol(p: SvcPart['protocol']): Obj | undefined {
  if (p === 'tcp_udp') return { type: 'PRESET', preset: { name: 'TCP_UDP' } };
  if (p === 'tcp') return { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: 'TCP' } };
  if (p === 'udp') return { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: 'UDP' } };
  return undefined;
}

export function integrationBody(r: RuleSpec): Obj {
  const sf = integrationFilter(r.src, null);
  const df = integrationFilter(r.dst, r.svc.ports);
  const proto = integrationProtocol(r.svc.protocol);
  return {
    name: r.name,
    description: r.description,
    enabled: true,
    action: r.action === 'ALLOW' ? { type: 'ALLOW', allowReturnTraffic: false } : { type: 'BLOCK' },
    source: { zoneId: r.srcZoneId, ...(sf ? { trafficFilter: sf } : {}) },
    destination: { zoneId: r.dstZoneId, ...(df ? { trafficFilter: df } : {}) },
    ipProtocolScope: { ipVersion: r.ipVersion === 'v4' ? 'IPV4' : 'IPV4_AND_IPV6', ...(proto ? { protocolFilter: proto } : {}) },
    ...(r.states === 'new' ? { connectionStateFilter: ['NEW', 'INVALID'] } : {}),
    loggingEnabled: false,
  };
}

function v2Endpoint(ep: EndpointSpec, zoneId: string | null, ports: string | null, side: 'src' | 'dst'): Obj {
  const base: Obj = {
    zone_id: zoneId,
    port_matching_type: ports ? 'SPECIFIC' : 'ANY',
    ...(ports ? { port: ports } : {}),
    match_opposite_ports: false,
    ...(side === 'src' ? { match_mac: false } : {}),
  };
  switch (ep.kind) {
    case 'any':
      return { ...base, matching_target: 'ANY' };
    case 'networks':
      return { ...base, matching_target: 'NETWORK', network_ids: ep.ids, match_opposite_networks: false };
    case 'ips':
      return { ...base, matching_target: 'IP', matching_target_type: 'SPECIFIC', ips: ep.values, match_opposite_ips: false };
    case 'list':
      return { ...base, matching_target: 'IP', matching_target_type: 'OBJECT', ip_group_id: ep.id, match_opposite_ips: false };
    case 'regions':
      // The planner only builds country rules for the official API; this is never sent.
      throw new Error('Country rules need the official UniFi API (Network 10.1 or newer).');
  }
}

/** An existing official-API policy with its source country list replaced. */
export function withRegions(raw: Obj, regions: string[]): Obj {
  const src = (raw.source ?? {}) as Obj;
  const tf = (src.trafficFilter ?? {}) as Obj;
  return { ...raw, source: { ...src, trafficFilter: { ...tf, type: 'REGION', regionFilter: { ...((tf.regionFilter ?? {}) as Obj), regions } } } };
}

export function v2Body(r: RuleSpec): Obj {
  return {
    name: r.name,
    description: r.description,
    enabled: true,
    action: r.action,
    create_allow_respond: false,
    ip_version: r.ipVersion === 'v4' ? 'IPV4' : 'BOTH',
    logging: false,
    protocol: r.svc.protocol,
    match_opposite_protocol: false,
    connection_state_type: r.states === 'new' ? 'CUSTOM' : 'ALL',
    connection_states: r.states === 'new' ? ['NEW', 'INVALID'] : [],
    match_ip_sec: false,
    icmp_typename: 'ANY',
    icmp_v6_typename: 'ANY',
    schedule: { mode: 'ALWAYS' },
    source: v2Endpoint(r.src, r.srcZoneId, null, 'src'),
    destination: v2Endpoint(r.dst, r.dstZoneId, r.svc.ports, 'dst'),
  };
}

export function legacyBody(r: RuleSpec): Obj {
  const side = (ep: EndpointSpec) => ({
    firewallgroup_ids: ep.kind === 'list' ? [ep.id] : [],
    address: ep.kind === 'ips' ? ep.values[0] : '',
    networkconf_id: ep.kind === 'networks' ? ep.ids[0] : '',
  });
  const s = side(r.src);
  const d = side(r.dst);
  return {
    name: r.name,
    enabled: true,
    action: r.action === 'ALLOW' ? 'accept' : 'drop',
    ruleset: r.ruleset,
    rule_index: r.ruleIndex,
    protocol: r.svc.protocol,
    protocol_match_excepted: false,
    logging: false,
    state_new: r.states === 'new',
    state_established: false,
    state_related: false,
    state_invalid: r.states === 'new',
    src_firewallgroup_ids: s.firewallgroup_ids,
    src_mac_address: '',
    src_address: s.address,
    src_networkconf_id: s.networkconf_id,
    src_networkconf_type: 'NETv4',
    dst_firewallgroup_ids: d.firewallgroup_ids,
    dst_address: d.address,
    dst_networkconf_id: d.networkconf_id,
    dst_networkconf_type: 'NETv4',
    dst_port: r.svc.ports ?? '',
    ipsec: '',
  };
}

export function ruleBody(dialect: Dialect, r: RuleSpec): Obj {
  return dialect === 'integration' ? integrationBody(r) : dialect === 'internal-v2' ? v2Body(r) : legacyBody(r);
}

export type ApiKind = 'integration' | 'v1' | 'v2';

export function rulePath(dialect: Dialect, id?: string): { kind: ApiKind; sub: string } {
  if (dialect === 'integration') return { kind: 'integration', sub: `/firewall/policies${id ? `/${id}` : ''}` };
  if (dialect === 'internal-v2') return { kind: 'v2', sub: `/firewall-policies${id ? `/${id}` : ''}` };
  return { kind: 'v1', sub: `/rest/firewallrule${id ? `/${id}` : ''}` };
}

/** Strip read-only fields so an object read from the API can be PUT back. */
export function forPut(dialect: Dialect, raw: Obj): Obj {
  const copy = structuredClone(raw) as Obj;
  if (dialect === 'integration') {
    delete copy.id;
    delete copy.index;
    delete copy.metadata;
  }
  return copy;
}

// --- Mutations of existing rules (extend / widen) -----------------------------------

export function withSourceNetworks(dialect: Dialect, raw: Obj, ids: string[]): Obj {
  const b = forPut(dialect, raw);
  if (dialect === 'integration') {
    const src = b.source as Obj;
    const tf = (src.trafficFilter ?? {}) as Obj;
    src.trafficFilter = { ...tf, type: 'NETWORK', networkFilter: { ...((tf.networkFilter as Obj) ?? {}), networkIds: ids, matchOpposite: false } };
  } else if (dialect === 'internal-v2') {
    (b.source as Obj).network_ids = ids;
  }
  return b;
}

export function withDestinationNetworks(dialect: Dialect, raw: Obj, ids: string[]): Obj {
  const b = forPut(dialect, raw);
  if (dialect === 'integration') {
    const dst = b.destination as Obj;
    const tf = (dst.trafficFilter ?? {}) as Obj;
    dst.trafficFilter = { ...tf, type: 'NETWORK', networkFilter: { ...((tf.networkFilter as Obj) ?? {}), networkIds: ids, matchOpposite: false } };
  } else if (dialect === 'internal-v2') {
    (b.destination as Obj).network_ids = ids;
  }
  return b;
}

export function withService(dialect: Dialect, raw: Obj, svc: SvcPart): Obj {
  const b = forPut(dialect, raw);
  if (dialect === 'integration') {
    const scope = b.ipProtocolScope as Obj;
    const proto = integrationProtocol(svc.protocol);
    if (proto) scope.protocolFilter = proto;
    else delete scope.protocolFilter;
    const dst = b.destination as Obj;
    const tf = (dst.trafficFilter ?? null) as Obj | null;
    if (svc.ports) {
      if (!tf) dst.trafficFilter = { type: 'PORT', portFilter: integrationPortFilter(svc.ports) };
      else tf.portFilter = integrationPortFilter(svc.ports);
    } else if (tf) {
      // Widening to every port: drop the old port filter too, or the rule keeps matching only those ports.
      if (tf.type === 'PORT') delete dst.trafficFilter;
      else delete tf.portFilter;
    }
  } else if (dialect === 'internal-v2') {
    b.protocol = svc.protocol;
    const dst = b.destination as Obj;
    dst.port_matching_type = svc.ports ? 'SPECIFIC' : 'ANY';
    if (svc.ports) dst.port = svc.ports;
    else delete dst.port;
  } else {
    b.protocol = svc.protocol;
    b.dst_port = svc.ports ?? '';
  }
  return b;
}
