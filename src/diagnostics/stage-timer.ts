/**
 * Minimal per-stage timing helper (Phase 4 operability).
 *
 * Measures elapsed time between `mark()` calls and emits `[timing]` log lines
 * such as `[timing] inventory: 981ms (881 docs)`. Purely internal, no
 * dependencies; the `log` callback decides the destination (stderr JSON Lines
 * via the diagnostics logger, or the `[auto-arm]` stdout lines). When no log
 * callback is wired the caller simply never constructs a timer.
 */
export interface StageTimer {
  /**
   * Log the elapsed time since the previous `mark()` (or timer creation) and
   * reset the interval so consecutive marks report per-stage durations.
   */
  mark(stage: string, detail?: string): void;
}

export function createStageTimer(log: (msg: string) => void): StageTimer {
  let previous = performance.now();
  return {
    mark(stage: string, detail?: string): void {
      const now = performance.now();
      const elapsed = Math.round(now - previous);
      previous = now;
      log(`[timing] ${stage}: ${elapsed}ms${detail ? ` (${detail})` : ''}`);
    },
  };
}
