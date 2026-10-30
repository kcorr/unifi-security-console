import { useMemo, useState } from 'react';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import type { Feature, FeatureCollection, Geometry } from 'geojson';
import type { GeometryCollection, Topology } from 'topojson-specification';
import countries from 'i18n-iso-countries';
import world from 'world-atlas/countries-110m.json';
import { countryName, fmtNum } from '../lib/format';

const W = 960;
const H = 470;

const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
const shapes = feature(topo, topo.objects.countries) as FeatureCollection<Geometry, { name: string }>;
const projection = geoNaturalEarth1().fitSize([W, H], shapes);
const path = geoPath(projection);
const PATHS = shapes.features.map((f) => ({ id: String((f as Feature).id ?? ''), name: f.properties?.name ?? '', d: path(f) ?? '' }));

function color(t: number): string {
  // cyan → amber → rose
  const stops = [
    [34, 211, 238],
    [251, 191, 36],
    [244, 63, 94],
  ];
  const x = Math.max(0, Math.min(1, t)) * (stops.length - 1);
  const i = Math.min(stops.length - 2, Math.floor(x));
  const f = x - i;
  const c = stops[i].map((v, k) => Math.round(v + (stops[i + 1][k] - v) * f));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}

export function WorldMap({ data, onSelect }: { data: { country: string; count: number }[]; onSelect?: (code: string) => void }) {
  const [hover, setHover] = useState<{ code: string; name: string; count: number; x: number; y: number } | null>(null);
  const byNumeric = useMemo(() => {
    const m = new Map<string, { code: string; count: number }>();
    for (const d of data) {
      const n = countries.alpha2ToNumeric(d.country.toUpperCase());
      if (n) m.set(String(Number(n)), { code: d.country.toUpperCase(), count: d.count });
    }
    return m;
  }, [data]);
  const max = Math.max(1, ...data.map((d) => d.count));

  return (
    <div className="relative w-full">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img" aria-label="Map of threat sources by country">
        {PATHS.map((p) => {
          const hit = byNumeric.get(String(Number(p.id)));
          const fill = hit ? color(Math.log(hit.count + 1) / Math.log(max + 1)) : '#1a2338';
          return (
            <path
              key={p.id + p.name}
              d={p.d}
              fill={fill}
              fillOpacity={hit ? 0.85 : 1}
              stroke="#0a0e18"
              strokeWidth={0.5}
              className={hit && onSelect ? 'cursor-pointer' : undefined}
              onMouseMove={(e) => {
                const svg = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
                setHover({ code: hit?.code ?? '', name: hit ? countryName(hit.code) : p.name, count: hit?.count ?? 0, x: e.clientX - svg.left, y: e.clientY - svg.top });
              }}
              onMouseLeave={() => setHover(null)}
              onClick={() => hit && onSelect?.(hit.code)}
            />
          );
        })}
      </svg>
      {hover && (
        <div className="pointer-events-none absolute z-10 rounded-lg border border-line-2 bg-[#0f1729] px-2.5 py-1.5 text-xs shadow-xl" style={{ left: Math.min(hover.x + 12, 9999), top: hover.y + 12 }}>
          <div className="font-medium text-ink">{hover.name}</div>
          <div className="text-ink-3">{hover.count ? `${fmtNum(hover.count)} detection${hover.count === 1 ? '' : 's'}` : 'No detections'}</div>
        </div>
      )}
    </div>
  );
}
