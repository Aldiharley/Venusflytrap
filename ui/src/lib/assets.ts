// Generated art is untracked until its licence is confirmed (console spec §11), so it is
// globbed: a checkout without it still builds and the images are simply absent.
const props = import.meta.glob('../../assets/props/*.webp', { eager: true, query: '?url', import: 'default' }) as Record<string, string>;
const scenes = import.meta.glob('../../assets/scenes/*.webp', { eager: true, query: '?url', import: 'default' }) as Record<string, string>;

export type PropName =
  | 'base-plate' | 'edge-gateway' | 'source-pod' | 'shield-tower' | 'route-block'
  | 'honeypot-flytrap' | 'quarantine-cage' | 'junction-box';
export type SceneName = 'quiet' | 'disconnected' | 'not-built' | 'no-results';

export const propUrl = (name: PropName): string | undefined => props[`../../assets/props/${name}.webp`];
export const sceneUrl = (name: SceneName): string | undefined => scenes[`../../assets/scenes/${name}.webp`];
