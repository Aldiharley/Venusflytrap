// The keyboard model shared by the console's data grids (role="grid", one tab stop, UX §5 and §7).
export interface Cell { r: number; c: number }

export function moveCell(p: Cell, key: string, mods: { ctrl: boolean }, dims: { rows: number; cols: number }): Cell | null {
  const clampR = (r: number) => Math.max(0, Math.min(dims.rows - 1, r));
  const clampC = (c: number) => Math.max(0, Math.min(dims.cols - 1, c));
  switch (key) {
    case 'ArrowRight': return { r: p.r, c: clampC(p.c + 1) };
    case 'ArrowLeft': return { r: p.r, c: clampC(p.c - 1) };
    case 'ArrowDown': return { r: clampR(p.r + 1), c: p.c };
    case 'ArrowUp': return { r: clampR(p.r - 1), c: p.c };
    case 'Home': return mods.ctrl ? { r: 0, c: 0 } : { r: p.r, c: 0 };
    case 'End': return mods.ctrl ? { r: dims.rows - 1, c: dims.cols - 1 } : { r: p.r, c: dims.cols - 1 };
    case 'PageDown': return { r: clampR(p.r + 10), c: p.c };
    case 'PageUp': return { r: clampR(p.r - 10), c: p.c };
    default: return null;
  }
}
