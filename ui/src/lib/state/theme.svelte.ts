export type ThemePref = 'light' | 'dark' | 'system';
const KEY = 'vft-theme';

function stored(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch {
    return 'system';
  }
}

class Theme {
  pref = $state<ThemePref>(stored());

  set(p: ThemePref) {
    this.pref = p;
    try {
      localStorage.setItem(KEY, p);
    } catch {
      // Storage blocked: the choice lasts for this page only.
    }
    this.apply();
  }

  apply() {
    const root = document.documentElement;
    if (this.pref === 'system') delete root.dataset.theme;
    else root.dataset.theme = this.pref;
  }
}

class Motion {
  paused = $state(false);

  set(paused: boolean) {
    this.paused = paused;
    if (paused) document.documentElement.dataset.motion = 'off';
    else delete document.documentElement.dataset.motion;
  }

  /** True when nothing may animate: the OS setting or the in-app Pause. */
  get reduced(): boolean {
    return this.paused || window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }
}

export const theme = new Theme();
export const motion = new Motion();
