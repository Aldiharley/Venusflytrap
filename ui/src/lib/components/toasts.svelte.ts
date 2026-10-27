export type Tone = 'info' | 'success' | 'warn' | 'error';
export interface Toast { id: number; tone: Tone; text: string }

class Toasts {
  items = $state<Toast[]>([]);
  private next = 1;

  push(t: { tone: Tone; text: string }) {
    const toast = { id: this.next++, ...t };
    this.items = [...this.items, toast].slice(-3);
    if (t.tone !== 'error') setTimeout(() => this.dismiss(toast.id), 6000);
  }

  dismiss(id: number) {
    this.items = this.items.filter((t) => t.id !== id);
  }
}

export const toasts = new Toasts();
