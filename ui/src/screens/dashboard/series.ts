/** Closed SVG area paths for stacked series (index 0 at the bottom). */
export function stackedPaths(series: number[][], w: number, h: number): { d: string; max: number }[] {
  const n = series[0]?.length ?? 0;
  const tops: number[][] = [];
  let acc = new Array<number>(n).fill(0);
  for (const s of series) {
    acc = acc.map((v, i) => v + (s[i] ?? 0));
    tops.push([...acc]);
  }
  const max = Math.max(1, ...acc);
  const x = (i: number) => (n <= 1 ? 0 : (i / (n - 1)) * w);
  const y = (v: number) => h - (v / max) * h;
  return tops.map((top, k) => {
    const bottom = k === 0 ? new Array<number>(n).fill(0) : tops[k - 1];
    // Every path starts at x = 0 ("M0,…").
    const up = top.map((v, i) => `${i === 0 ? 'M0' : `L${x(i).toFixed(1)}`},${y(v).toFixed(1)}`).join(' ');
    const down = bottom
      .map((v, i) => [i, v] as const)
      .reverse()
      .map(([i, v]) => `L${x(i).toFixed(1)},${y(v).toFixed(1)}`)
      .join(' ');
    return { d: `${up} ${down} Z`, max: Math.max(0, ...top) };
  });
}
