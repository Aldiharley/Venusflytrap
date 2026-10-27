export type RouteName =
  | 'dashboard' | 'topology' | 'monitor' | 'chains' | 'honeypot' | 'settings' | 'keys'
  | 'request' | 'source' | 'notfound';
export interface Route { name: RouteName; param: string | null }

const TABLE: [RegExp, RouteName][] = [
  [/^\/$/, 'dashboard'],
  [/^\/topology$/, 'topology'],
  [/^\/monitor$/, 'monitor'],
  [/^\/chains$/, 'chains'],
  [/^\/honeypot$/, 'honeypot'],
  [/^\/settings$/, 'settings'],
  [/^\/keys$/, 'keys'],
  [/^\/requests\/([^/]+)$/, 'request'],
  [/^\/sources\/([^/]+)$/, 'source'],
];

export function match(path: string): Route {
  for (const [re, name] of TABLE) {
    const m = path.match(re);
    if (!m) continue;
    if (m[1] === undefined) return { name, param: null };
    try {
      return { name, param: decodeURIComponent(m[1]) };
    } catch {
      // A malformed escape (e.g. /requests/%) must not take the whole app down.
      return { name: 'notfound', param: null };
    }
  }
  return { name: 'notfound', param: null };
}

export const NAV: { name: RouteName; href: string; label: string; adminOnly?: boolean }[] = [
  { name: 'dashboard', href: '/', label: 'Dashboard' },
  { name: 'topology', href: '/topology', label: 'Traffic topology' },
  { name: 'monitor', href: '/monitor', label: 'Monitor' },
  { name: 'chains', href: '/chains', label: 'Attack chains' },
  { name: 'honeypot', href: '/honeypot', label: 'Honeypot & bans' },
  { name: 'settings', href: '/settings', label: 'Settings' },
  { name: 'keys', href: '/keys', label: 'Keys', adminOnly: true },
];

/** Detail routes mark their parent as current in the nav (UX §2.2). */
export const PARENT: Partial<Record<RouteName, RouteName>> = { request: 'monitor', source: 'chains' };

class Router {
  path = $state(location.pathname);
  search = $state(new URLSearchParams(location.search));
  route = $derived(match(this.path));

  constructor() {
    window.addEventListener('popstate', () => this.sync());
  }

  navigate(href: string, replace = false) {
    if (replace) history.replaceState(null, '', href);
    else history.pushState(null, '', href);
    this.sync();
  }

  private sync() {
    this.path = location.pathname;
    this.search = new URLSearchParams(location.search);
  }
}

export const router = new Router();
