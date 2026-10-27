import type { PropName } from '../../lib/assets';

export const SCENE = { w: 960, h: 720 } as const;
export interface Box { x: number; y: number; w: number; prop: PropName }

export type NodeId =
  | 'clean' | 'recon' | 'exploit' | 'tower'
  | 'route0' | 'route1' | 'route2' | 'route3' | 'route4'
  | 'hp0' | 'hp1' | 'hp2' | 'hp3' | 'quarantine';
export type DecorId = 'edge' | 'jA' | 'jB';

export const PLATE: Box = { x: 30, y: 120, w: 900, prop: 'base-plate' };

export const BOX: Record<NodeId | DecorId, Box> = {
  edge: { x: 40, y: 250, w: 70, prop: 'edge-gateway' },
  clean: { x: 150, y: 262, w: 64, prop: 'source-pod' },
  recon: { x: 170, y: 352, w: 64, prop: 'source-pod' },
  exploit: { x: 190, y: 442, w: 64, prop: 'source-pod' },
  jA: { x: 300, y: 350, w: 54, prop: 'junction-box' },
  tower: { x: 400, y: 170, w: 150, prop: 'shield-tower' },
  jB: { x: 560, y: 300, w: 46, prop: 'junction-box' },
  route0: { x: 600, y: 160, w: 68, prop: 'route-block' },
  route1: { x: 660, y: 220, w: 68, prop: 'route-block' },
  route2: { x: 720, y: 280, w: 68, prop: 'route-block' },
  route3: { x: 780, y: 340, w: 68, prop: 'route-block' },
  route4: { x: 840, y: 400, w: 68, prop: 'route-block' },
  hp0: { x: 560, y: 432, w: 64, prop: 'honeypot-flytrap' },
  hp1: { x: 640, y: 492, w: 64, prop: 'honeypot-flytrap' },
  hp2: { x: 720, y: 552, w: 64, prop: 'honeypot-flytrap' },
  hp3: { x: 800, y: 492, w: 64, prop: 'honeypot-flytrap' },
  quarantine: { x: 420, y: 500, w: 130, prop: 'quarantine-cage' },
};

/** Line end points (plate centres). */
export const ANCHOR: Record<NodeId | DecorId | 'stub', [number, number]> = {
  edge: [90, 400], clean: [182, 290], recon: [202, 376], exploit: [222, 466],
  jA: [327, 374], tower: [470, 350], jB: [583, 320],
  route0: [634, 236], route1: [694, 294], route2: [754, 352], route3: [814, 410], route4: [874, 470],
  hp0: [592, 478], hp1: [672, 538], hp2: [752, 598], hp3: [832, 538],
  quarantine: [485, 548], stub: [330, 230],
};

/** Roving-tabindex order (UX §4): Clean → Recon → Exploitation → Tower → Routes → Pods → Quarantine. */
export const ORDER: NodeId[] = ['clean', 'recon', 'exploit', 'tower', 'route0', 'route1', 'route2', 'route3', 'route4', 'hp0', 'hp1', 'hp2', 'hp3', 'quarantine'];

export const pct = (v: number, of: number) => `${((v / of) * 100).toFixed(3)}%`;
