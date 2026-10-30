import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { ClientTraffic, liveTrend, usageByMac } from './live.ts';

test('live history: any range, averaged into buckets, with peaks and data used', () => {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE live_samples (t INTEGER PRIMARY KEY, rx REAL, tx REAL, latency REAL, clients REAL, cpu REAL, mem REAL)');
  const now = 1_800_000_000_000;
  const spike = now - 600e3;
  // Two hours of 5-second samples: 8 Mbps down (1 MB/s), 1 Mbps up, and one 100 Mbps spike.
  const insert = db.prepare('INSERT INTO live_samples VALUES (?, ?, ?, ?, ?, ?, ?)');
  for (let t = now - 2 * 3600e3; t <= now; t += 5000) insert.run(t, t === spike ? 100e6 : 8e6, 1e6, 20, 10, 30, 50);

  const hour = liveTrend(db, '1h', now);
  assert.equal(hour.bucketMs, 5000, 'up to an hour, every sample is its own point');
  assert.equal(hour.points.length, 721);
  assert.deepEqual(hour.summary.peakRx, { bps: 100e6, t: spike });
  const expected = 3600 * 1e6 + (5 * (100e6 - 8e6)) / 8;
  assert.ok(Math.abs(hour.summary.rxBytes - expected) < 1e6, `${hour.summary.rxBytes} vs ${expected}`);

  const day = liveTrend(db, '24h', now);
  assert.equal(day.bucketMs, 120_000, 'a day is averaged into 2-minute points');
  assert.equal(day.summary.since, now - 2 * 3600e3, 'history only reaches back as far as it was kept');
  assert.ok(day.points.every((p) => (p.rxMax ?? 0) >= (p.rxBps ?? 0)), 'each point keeps the peak hidden in its average');
  assert.equal(Math.max(...day.points.map((p) => p.rxMax ?? 0)), 100e6);
});

test('last-24-hour usage adds up the hourly report rows of each device', () => {
  const m = usageByMac([
    { user: 'AA:BB:CC:00:00:01', rx_bytes: 100, tx_bytes: 10 },
    { user: 'aa:bb:cc:00:00:01', rx_bytes: 50, tx_bytes: 5 },
    { user: 'aa:bb:cc:00:00:02', rx_bytes: 7 },
  ]);
  assert.deepEqual(m.get('aa:bb:cc:00:00:01'), { rx: 150, tx: 15 }, 'MACs match whatever their case');
  assert.deepEqual(m.get('aa:bb:cc:00:00:02'), { rx: 7, tx: 0 });
});

test('wired devices: their download is what the switch port sends, and live rates come from counter growth', () => {
  const t = new ClientTraffic();
  const wired = (down: number, up: number) => ({ mac: 'AA:BB:CC:00:00:09', is_wired: true, 'wired-tx_bytes': down, 'wired-rx_bytes': up });
  assert.deepEqual(t.read(wired(1_000, 500), 0), { down: 1_000, up: 500, downBps: 0, upBps: 0 }, 'no rate before a second reading');
  assert.deepEqual(t.read(wired(126_000, 1_750), 10_000), { down: 126_000, up: 1_750, downBps: 100_000, upBps: 1_000 });
  assert.equal(t.read(wired(10, 10), 20_000).downBps, 0, 'a counter that went backwards means the device reconnected');
  assert.deepEqual(t.read({ mac: 'aa:bb:cc:00:00:0a', rx_bytes: 5, tx_bytes: 6, 'rx_bytes-r': 100, 'tx_bytes-r': 10 }, 0), { down: 5, up: 6, downBps: 800, upBps: 80 }, 'Wi-Fi clients report from their own side');
});
