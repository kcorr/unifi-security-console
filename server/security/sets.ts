// Set algebra used by the firewall analyzer.
//
// Every firewall rule (existing or proposed) is reduced to a "traffic space": a union of
// boxes, each box being (address family, source addresses, destination addresses,
// services, connection states). Comparing rules then becomes set math (subset / overlap /
// difference) instead of string comparison, which is what lets us recognise that
// "UDP+TCP 53 from 10.0.30.0/24" and "DNS from the IoT network" are the same rule.

export type Iv = readonly [bigint, bigint]; // inclusive interval

function normalize(ivs: readonly Iv[]): Iv[] {
  if (ivs.length === 0) return [];
  const sorted = ivs.filter((iv) => iv[0] <= iv[1]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const out: [bigint, bigint][] = [];
  for (const [s, e] of sorted) {
    const last = out[out.length - 1];
    if (last && s <= last[1] + 1n) {
      if (e > last[1]) last[1] = e;
    } else {
      out.push([s, e]);
    }
  }
  return out;
}

/** Sorted, disjoint set of inclusive bigint intervals. Immutable. */
export class RangeSet {
  readonly ivs: readonly Iv[];

  constructor(ivs: readonly Iv[] = [], normalized = false) {
    this.ivs = normalized ? ivs : normalize(ivs);
  }

  static of(lo: bigint, hi: bigint): RangeSet {
    return new RangeSet([[lo, hi]], true);
  }

  isEmpty(): boolean {
    return this.ivs.length === 0;
  }

  union(o: RangeSet): RangeSet {
    if (o.isEmpty()) return this;
    if (this.isEmpty()) return o;
    return new RangeSet([...this.ivs, ...o.ivs]);
  }

  intersect(o: RangeSet): RangeSet {
    const a = this.ivs;
    const b = o.ivs;
    const out: Iv[] = [];
    let i = 0;
    let j = 0;
    while (i < a.length && j < b.length) {
      const lo = a[i][0] > b[j][0] ? a[i][0] : b[j][0];
      const hi = a[i][1] < b[j][1] ? a[i][1] : b[j][1];
      if (lo <= hi) out.push([lo, hi]);
      if (a[i][1] < b[j][1]) i++;
      else j++;
    }
    return new RangeSet(out, true);
  }

  subtract(o: RangeSet): RangeSet {
    if (this.isEmpty() || o.isEmpty()) return this;
    const out: Iv[] = [];
    const b = o.ivs;
    let j = 0;
    for (const [s0, e] of this.ivs) {
      let s = s0;
      while (j < b.length && b[j][1] < s) j++;
      let k = j;
      while (k < b.length && b[k][0] <= e && s <= e) {
        if (b[k][0] > s) out.push([s, b[k][0] - 1n]);
        if (b[k][1] + 1n > s) s = b[k][1] + 1n;
        k++;
      }
      if (s <= e) out.push([s, e]);
    }
    return new RangeSet(out, true);
  }

  /** True when every element of `o` is in this set. */
  contains(o: RangeSet): boolean {
    return o.subtract(this).isEmpty();
  }

  overlaps(o: RangeSet): boolean {
    return !this.intersect(o).isEmpty();
  }

  equals(o: RangeSet): boolean {
    if (this.ivs.length !== o.ivs.length) return false;
    return this.ivs.every((iv, i) => iv[0] === o.ivs[i][0] && iv[1] === o.ivs[i][1]);
  }

  size(): bigint {
    let n = 0n;
    for (const [s, e] of this.ivs) n += e - s + 1n;
    return n;
  }

  key(): string {
    return this.ivs.map(([s, e]) => (s === e ? `${s}` : `${s}-${e}`)).join(',');
  }
}

// ---------------------------------------------------------------------------------
// IP addresses
// ---------------------------------------------------------------------------------

export const V4_MAX = (1n << 32n) - 1n;
export const V6_MAX = (1n << 128n) - 1n;
const V4_ALL = RangeSet.of(0n, V4_MAX);
const V6_ALL = RangeSet.of(0n, V6_MAX);

export function parseIPv4(s: string): bigint | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  let n = 0n;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = (n << 8n) | BigInt(o);
  }
  return n;
}

export function parseIPv6(input: string): bigint | null {
  let s = input.trim().toLowerCase();
  const pct = s.indexOf('%');
  if (pct >= 0) s = s.slice(0, pct);
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (!s.includes(':')) return null;
  // Embedded IPv4 tail, e.g. ::ffff:192.168.1.1 or 64:ff9b::1.2.3.4
  let tail: number[] = [];
  const lastColon = s.lastIndexOf(':');
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes('.')) {
    const v4 = parseIPv4(maybeV4);
    if (v4 === null) return null;
    tail = [Number((v4 >> 16n) & 0xffffn), Number(v4 & 0xffffn)];
    s = s.slice(0, lastColon + 1);
    if (!s.endsWith('::')) s = s.slice(0, -1);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (part: string): number[] | null => {
    if (part === '') return [];
    const groups = part.split(':');
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parseGroups(halves[0]);
  const rest = halves.length === 2 ? parseGroups(halves[1]) : [];
  if (!head || !rest) return null;
  const total = head.length + rest.length + tail.length;
  let groups: number[];
  if (halves.length === 2) {
    if (total > 7) return null;
    groups = [...head, ...new Array(8 - total).fill(0), ...rest, ...tail];
  } else {
    if (total !== 8) return null;
    groups = [...head, ...tail];
  }
  let n = 0n;
  for (const g of groups) n = (n << 16n) | BigInt(g);
  return n;
}

export type IpFamily = 4 | 6;

export function parseIp(s: string): { fam: IpFamily; n: bigint } | null {
  const v4 = parseIPv4(s);
  if (v4 !== null) return { fam: 4, n: v4 };
  const v6 = parseIPv6(s);
  if (v6 !== null) return { fam: 6, n: v6 };
  return null;
}

export function formatIPv4(n: bigint): string {
  return [24n, 16n, 8n, 0n].map((sh) => Number((n >> sh) & 0xffn)).join('.');
}

export function formatIPv6(n: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  // Find the longest run of zero groups (length >= 2) to compress.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart < 0) return hex.join(':');
  const left = hex.slice(0, bestStart).join(':');
  const right = hex.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

export function formatIp(fam: IpFamily, n: bigint): string {
  return fam === 4 ? formatIPv4(n) : formatIPv6(n);
}

function cidrRange(fam: IpFamily, n: bigint, prefix: number): Iv {
  const bits = fam === 4 ? 32n : 128n;
  const host = bits - BigInt(prefix);
  const mask = host === 0n ? 0n : (1n << host) - 1n;
  const start = n & ~mask & (fam === 4 ? V4_MAX : V6_MAX);
  return [start, start | mask];
}

/** Decompose an interval into the minimal list of CIDR blocks. */
function rangeToCidrs(fam: IpFamily, lo: bigint, hi: bigint, limit = 16): string[] | null {
  const bits = fam === 4 ? 32 : 128;
  const out: string[] = [];
  let cur = lo;
  while (cur <= hi) {
    let size = 0; // host bits
    while (size < bits) {
      const blk = 1n << BigInt(size + 1);
      if ((cur & (blk - 1n)) !== 0n) break;
      if (cur + blk - 1n > hi) break;
      size++;
    }
    out.push(`${formatIp(fam, cur)}/${bits - size}`);
    if (out.length > limit) return null;
    cur += 1n << BigInt(size);
  }
  return out;
}

/** A set of IPv4 + IPv6 addresses. */
export class AddrSet {
  readonly v4: RangeSet;
  readonly v6: RangeSet;

  constructor(v4: RangeSet = new RangeSet(), v6: RangeSet = new RangeSet()) {
    this.v4 = v4;
    this.v6 = v6;
  }

  static readonly ANY = new AddrSet(V4_ALL, V6_ALL);
  static readonly EMPTY = new AddrSet();
  static readonly V4_ANY = new AddrSet(V4_ALL, new RangeSet());
  static readonly V6_ANY = new AddrSet(new RangeSet(), V6_ALL);

  /**
   * Parse "10.0.0.1", "10.0.0.0/24", "192.168.1.1/24" (host bits are masked),
   * "10.0.0.5-10.0.0.20", "fd00::/64", "any". Returns null when unparseable.
   */
  static parse(spec: string): AddrSet | null {
    const s = spec.trim();
    if (!s) return null;
    if (/^(any|all|\*|0\.0\.0\.0\/0)$/i.test(s)) return s.startsWith('0.') ? AddrSet.V4_ANY : AddrSet.ANY;
    if (s === '::/0') return AddrSet.V6_ANY;
    const dash = s.indexOf('-');
    if (dash > 0) {
      const a = parseIp(s.slice(0, dash));
      const b = parseIp(s.slice(dash + 1));
      if (!a || !b || a.fam !== b.fam) return null;
      const lo = a.n < b.n ? a.n : b.n;
      const hi = a.n < b.n ? b.n : a.n;
      return AddrSet.fromRange(a.fam, lo, hi);
    }
    const slash = s.indexOf('/');
    if (slash > 0) {
      const ip = parseIp(s.slice(0, slash));
      const prefix = Number(s.slice(slash + 1));
      if (!ip || !Number.isInteger(prefix) || prefix < 0 || prefix > (ip.fam === 4 ? 32 : 128)) return null;
      const [lo, hi] = cidrRange(ip.fam, ip.n, prefix);
      return AddrSet.fromRange(ip.fam, lo, hi);
    }
    const ip = parseIp(s);
    if (!ip) return null;
    return AddrSet.fromRange(ip.fam, ip.n, ip.n);
  }

  /** Parse a list, ignoring entries that cannot be parsed (returned in `invalid`). */
  static parseList(specs: readonly string[]): { set: AddrSet; invalid: string[] } {
    let set = AddrSet.EMPTY;
    const invalid: string[] = [];
    for (const spec of specs) {
      const p = AddrSet.parse(spec);
      if (p) set = set.union(p);
      else invalid.push(spec);
    }
    return { set, invalid };
  }

  static fromRange(fam: IpFamily, lo: bigint, hi: bigint): AddrSet {
    return fam === 4 ? new AddrSet(RangeSet.of(lo, hi), new RangeSet()) : new AddrSet(new RangeSet(), RangeSet.of(lo, hi));
  }

  fam(f: IpFamily): RangeSet {
    return f === 4 ? this.v4 : this.v6;
  }

  isEmpty(): boolean {
    return this.v4.isEmpty() && this.v6.isEmpty();
  }

  isAny(): boolean {
    return this.v4.equals(V4_ALL) && this.v6.equals(V6_ALL);
  }

  union(o: AddrSet): AddrSet {
    return new AddrSet(this.v4.union(o.v4), this.v6.union(o.v6));
  }

  intersect(o: AddrSet): AddrSet {
    return new AddrSet(this.v4.intersect(o.v4), this.v6.intersect(o.v6));
  }

  subtract(o: AddrSet): AddrSet {
    return new AddrSet(this.v4.subtract(o.v4), this.v6.subtract(o.v6));
  }

  /** Complement within the full v4+v6 space. */
  invert(): AddrSet {
    return AddrSet.ANY.subtract(this);
  }

  contains(o: AddrSet): boolean {
    return this.v4.contains(o.v4) && this.v6.contains(o.v6);
  }

  overlaps(o: AddrSet): boolean {
    return this.v4.overlaps(o.v4) || this.v6.overlaps(o.v6);
  }

  equals(o: AddrSet): boolean {
    return this.v4.equals(o.v4) && this.v6.equals(o.v6);
  }

  has(ip: string): boolean {
    const p = parseIp(ip);
    if (!p) return false;
    const rs = this.fam(p.fam);
    return rs.ivs.some(([s, e]) => p.n >= s && p.n <= e);
  }

  /** Human friendly rendering: CIDRs where compact, ranges otherwise. */
  toStrings(max = 12): string[] {
    if (this.isAny()) return ['any'];
    const out: string[] = [];
    const render = (fam: IpFamily, rs: RangeSet, all: RangeSet) => {
      if (rs.equals(all)) {
        out.push(fam === 4 ? 'any IPv4' : 'any IPv6');
        return;
      }
      for (const [lo, hi] of rs.ivs) {
        if (lo === hi) out.push(formatIp(fam, lo));
        else {
          const cidrs = rangeToCidrs(fam, lo, hi, 4);
          if (cidrs) out.push(...cidrs);
          else out.push(`${formatIp(fam, lo)}–${formatIp(fam, hi)}`);
        }
      }
    };
    render(4, this.v4, V4_ALL);
    render(6, this.v6, V6_ALL);
    if (out.length > max) return [...out.slice(0, max), `+${out.length - max} more`];
    return out;
  }
}

// ---------------------------------------------------------------------------------
// Ports / protocols / states
// ---------------------------------------------------------------------------------

export const PORTS_ALL = RangeSet.of(0n, 65535n);
export const PORTS_NONE = new RangeSet();

/** Parse "53", "53,853", "8000-8100", "8000:8100", "any". */
export function parsePorts(spec: string | number | null | undefined): RangeSet | null {
  if (spec === null || spec === undefined) return null;
  const s = String(spec).trim();
  if (!s) return null;
  if (/^(any|all|\*)$/i.test(s)) return PORTS_ALL;
  const ivs: Iv[] = [];
  for (const part of s.split(/[,\s]+/).filter(Boolean)) {
    const m = /^(\d{1,5})(?:\s*[-:]\s*(\d{1,5}))?$/.exec(part);
    if (!m) return null;
    const a = Number(m[1]);
    const b = m[2] !== undefined ? Number(m[2]) : a;
    if (a > 65535 || b > 65535) return null;
    ivs.push([BigInt(Math.min(a, b)), BigInt(Math.max(a, b))]);
  }
  return new RangeSet(ivs);
}

export function formatPorts(rs: RangeSet): string {
  if (rs.equals(PORTS_ALL)) return 'any port';
  return rs.ivs.map(([s, e]) => (s === e ? `${s}` : `${s}-${e}`)).join(', ');
}

const PROTO_ICMP = 1n;
const PROTO_TCP = 6n;
const PROTO_UDP = 17n;
const PROTO_ICMPV6 = 58n;
const OTHER_ALL = RangeSet.of(0n, 255n).subtract(new RangeSet([[PROTO_ICMP, PROTO_ICMP], [PROTO_TCP, PROTO_TCP], [PROTO_UDP, PROTO_UDP], [PROTO_ICMPV6, PROTO_ICMPV6]]));

export const PROTOCOL_NUMBERS: Record<string, number> = {
  icmp: 1, igmp: 2, ipip: 4, tcp: 6, egp: 8, udp: 17, ipv6: 41, rsvp: 46, gre: 47, esp: 50, ah: 51, icmpv6: 58, 'ipv6-icmp': 58, ospf: 89, vrrp: 112, l2tp: 115, sctp: 132,
};

/** Set of (protocol, destination port) combinations. */
export class ServiceSet {
  readonly tcp: RangeSet;
  readonly udp: RangeSet;
  readonly icmp: boolean;
  readonly icmpv6: boolean;
  readonly other: RangeSet; // other IP protocol numbers

  constructor(p: { tcp?: RangeSet; udp?: RangeSet; icmp?: boolean; icmpv6?: boolean; other?: RangeSet }) {
    this.tcp = p.tcp ?? PORTS_NONE;
    this.udp = p.udp ?? PORTS_NONE;
    this.icmp = p.icmp ?? false;
    this.icmpv6 = p.icmpv6 ?? false;
    this.other = p.other ?? new RangeSet();
  }

  static readonly ALL = new ServiceSet({ tcp: PORTS_ALL, udp: PORTS_ALL, icmp: true, icmpv6: true, other: OTHER_ALL });
  static readonly NONE = new ServiceSet({});

  static tcpUdp(ports: RangeSet = PORTS_ALL): ServiceSet {
    return new ServiceSet({ tcp: ports, udp: ports });
  }

  static tcp(ports: RangeSet = PORTS_ALL): ServiceSet {
    return new ServiceSet({ tcp: ports });
  }

  static udp(ports: RangeSet = PORTS_ALL): ServiceSet {
    return new ServiceSet({ udp: ports });
  }

  /**
   * Build from a protocol name/number plus optional destination ports.
   * Ports only constrain TCP/UDP; for "all" with ports we assume TCP+UDP (what UniFi does).
   */
  static fromProtocol(protocol: string | number | null | undefined, ports: RangeSet | null): ServiceSet | null {
    const p = protocol === null || protocol === undefined || protocol === '' ? 'all' : String(protocol).toLowerCase().trim();
    const pp = ports ?? PORTS_ALL;
    switch (p) {
      case 'all':
      case 'any':
        return ports && !ports.equals(PORTS_ALL) ? ServiceSet.tcpUdp(pp) : ServiceSet.ALL;
      case 'tcp_udp':
      case 'tcp/udp':
      case 'tcpudp':
        return ServiceSet.tcpUdp(pp);
      case 'tcp':
      case '6':
        return ServiceSet.tcp(pp);
      case 'udp':
      case '17':
        return ServiceSet.udp(pp);
      case 'icmp':
      case '1':
        return new ServiceSet({ icmp: true });
      case 'icmpv6':
      case 'ipv6-icmp':
      case '58':
        return new ServiceSet({ icmpv6: true });
      default: {
        const num = /^\d+$/.test(p) ? Number(p) : PROTOCOL_NUMBERS[p];
        if (num === undefined || num < 0 || num > 255) return null;
        return new ServiceSet({ other: RangeSet.of(BigInt(num), BigInt(num)) });
      }
    }
  }

  isEmpty(): boolean {
    return this.tcp.isEmpty() && this.udp.isEmpty() && !this.icmp && !this.icmpv6 && this.other.isEmpty();
  }

  isAll(): boolean {
    return this.equals(ServiceSet.ALL);
  }

  union(o: ServiceSet): ServiceSet {
    return new ServiceSet({
      tcp: this.tcp.union(o.tcp),
      udp: this.udp.union(o.udp),
      icmp: this.icmp || o.icmp,
      icmpv6: this.icmpv6 || o.icmpv6,
      other: this.other.union(o.other),
    });
  }

  intersect(o: ServiceSet): ServiceSet {
    return new ServiceSet({
      tcp: this.tcp.intersect(o.tcp),
      udp: this.udp.intersect(o.udp),
      icmp: this.icmp && o.icmp,
      icmpv6: this.icmpv6 && o.icmpv6,
      other: this.other.intersect(o.other),
    });
  }

  subtract(o: ServiceSet): ServiceSet {
    return new ServiceSet({
      tcp: this.tcp.subtract(o.tcp),
      udp: this.udp.subtract(o.udp),
      icmp: this.icmp && !o.icmp,
      icmpv6: this.icmpv6 && !o.icmpv6,
      other: this.other.subtract(o.other),
    });
  }

  invert(): ServiceSet {
    return ServiceSet.ALL.subtract(this);
  }

  contains(o: ServiceSet): boolean {
    return o.subtract(this).isEmpty();
  }

  equals(o: ServiceSet): boolean {
    return this.tcp.equals(o.tcp) && this.udp.equals(o.udp) && this.icmp === o.icmp && this.icmpv6 === o.icmpv6 && this.other.equals(o.other);
  }

  describe(): string {
    if (this.isAll()) return 'all traffic';
    if (this.isEmpty()) return 'nothing';
    const parts: string[] = [];
    if (!this.tcp.isEmpty() && this.tcp.equals(this.udp)) parts.push(`TCP/UDP ${formatPorts(this.tcp)}`);
    else {
      if (!this.tcp.isEmpty()) parts.push(`TCP ${formatPorts(this.tcp)}`);
      if (!this.udp.isEmpty()) parts.push(`UDP ${formatPorts(this.udp)}`);
    }
    if (this.icmp) parts.push('ICMP');
    if (this.icmpv6) parts.push('ICMPv6');
    if (!this.other.isEmpty()) {
      if (this.other.equals(OTHER_ALL)) parts.push('other protocols');
      else {
        const names = Object.fromEntries(Object.entries(PROTOCOL_NUMBERS).map(([k, v]) => [v, k.toUpperCase()]));
        const list: string[] = [];
        for (const [s, e] of this.other.ivs) for (let i = s; i <= e && list.length < 6; i++) list.push(names[Number(i)] ?? `proto ${i}`);
        parts.push(list.join(', '));
      }
    }
    return parts.join(' + ');
  }
}

/** Connection-state bit mask. */
export const ST_NEW = 1;
export const ST_EST = 2;
export const ST_REL = 4;
export const ST_INV = 8;
export const ST_ALL = 15;

export function describeStates(st: number): string {
  if (st === ST_ALL) return 'all connection states';
  const names: string[] = [];
  if (st & ST_NEW) names.push('new');
  if (st & ST_EST) names.push('established');
  if (st & ST_REL) names.push('related');
  if (st & ST_INV) names.push('invalid');
  return names.join('/') + ' connections';
}

// ---------------------------------------------------------------------------------
// Boxes and spaces
// ---------------------------------------------------------------------------------

export interface Box {
  fam: IpFamily;
  src: RangeSet;
  dst: RangeSet;
  svc: ServiceSet;
  st: number;
}

/** A union of boxes. */
export type Space = Box[];

export function boxIsEmpty(b: Box): boolean {
  return b.src.isEmpty() || b.dst.isEmpty() || b.svc.isEmpty() || b.st === 0;
}

export function boxIntersect(a: Box, b: Box): Box | null {
  if (a.fam !== b.fam) return null;
  const r: Box = { fam: a.fam, src: a.src.intersect(b.src), dst: a.dst.intersect(b.dst), svc: a.svc.intersect(b.svc), st: a.st & b.st };
  return boxIsEmpty(r) ? null : r;
}

/** a \ b as a list of disjoint boxes. */
export function boxSubtract(a: Box, b: Box): Box[] {
  if (a.fam !== b.fam || !boxIntersect(a, b)) return [a];
  const out: Box[] = [];
  const push = (x: Box) => {
    if (!boxIsEmpty(x)) out.push(x);
  };
  const srcIn = a.src.intersect(b.src);
  push({ ...a, src: a.src.subtract(b.src) });
  const dstIn = a.dst.intersect(b.dst);
  push({ ...a, src: srcIn, dst: a.dst.subtract(b.dst) });
  const svcIn = a.svc.intersect(b.svc);
  push({ ...a, src: srcIn, dst: dstIn, svc: a.svc.subtract(b.svc) });
  push({ ...a, src: srcIn, dst: dstIn, svc: svcIn, st: a.st & ~b.st });
  return out;
}

export function spaceIntersect(a: Space, b: Space): Space {
  const out: Space = [];
  for (const x of a) for (const y of b) {
    const i = boxIntersect(x, y);
    if (i) out.push(i);
  }
  return out;
}

export function spaceSubtract(a: Space, b: Space, maxBoxes = 4000): Space {
  let cur = a;
  for (const y of b) {
    const next: Space = [];
    for (const x of cur) next.push(...boxSubtract(x, y));
    cur = next;
    if (cur.length > maxBoxes) break;
  }
  return cur;
}

export function spaceIsEmpty(s: Space): boolean {
  return s.every(boxIsEmpty);
}

/** True when `outer` covers every packet in `inner`. */
export function spaceContains(outer: Space, inner: Space): boolean {
  return spaceIsEmpty(spaceSubtract(inner, outer));
}

/** Build a space from address sets (split per family; mismatched families are dropped). */
export function makeSpace(src: AddrSet, dst: AddrSet, svc: ServiceSet, st: number): Space {
  const out: Space = [];
  for (const fam of [4, 6] as const) {
    const b: Box = { fam, src: src.fam(fam), dst: dst.fam(fam), svc, st };
    if (!boxIsEmpty(b)) out.push(b);
  }
  return out;
}

export function spaceSrc(s: Space): AddrSet {
  let v4 = new RangeSet();
  let v6 = new RangeSet();
  for (const b of s) {
    if (b.fam === 4) v4 = v4.union(b.src);
    else v6 = v6.union(b.src);
  }
  return new AddrSet(v4, v6);
}

export function spaceDst(s: Space): AddrSet {
  let v4 = new RangeSet();
  let v6 = new RangeSet();
  for (const b of s) {
    if (b.fam === 4) v4 = v4.union(b.dst);
    else v6 = v6.union(b.dst);
  }
  return new AddrSet(v4, v6);
}

export function spaceSvc(s: Space): ServiceSet {
  return s.reduce((acc, b) => acc.union(b.svc), ServiceSet.NONE);
}

export function spaceFamilies(s: Space): IpFamily[] {
  return [...new Set(s.filter((b) => !boxIsEmpty(b)).map((b) => b.fam))].sort() as IpFamily[];
}
