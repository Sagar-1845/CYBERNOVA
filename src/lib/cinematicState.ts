/**
 * src/lib/cinematicState.ts
 * ─────────────────────────
 * High-performance, zero-React-re-render state management for Landing Hero.
 * Driven strictly from the GSAP ticker.
 */

export interface PointerState {
  targetX: number;
  targetY: number;
  currentX: number;
  currentY: number;
}

export type ChapterListener = (chapterIndex: number) => void;
export type InvalidateCallback = () => void;

class CinematicStateManager {
  public pointer: PointerState = {
    targetX: 0,
    targetY: 0,
    currentX: 0,
    currentY: 0,
  };

  public scrollProgress: number = 0;
  public targetScrollProgress: number = 0;
  public currentChapter: number = 0;
  public isMotionOn: boolean = true;
  public isVisible: boolean = true;
  public needsStillFrame: boolean = true;
  public time: number = 0;

  private chapterListeners: Set<ChapterListener> = new Set();
  private invalidateCallbacks: Set<InvalidateCallback> = new Set();
  private isPointerMoving: boolean = false;
  private pointerRestFrames: number = 0;

  constructor() {
    if (typeof window !== 'undefined') {
      this.isMotionOn = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
  }

  public registerInvalidate(cb: InvalidateCallback): () => void {
    this.invalidateCallbacks.add(cb);
    return () => this.invalidateCallbacks.delete(cb);
  }

  public invalidate(): void {
    if (!this.isVisible) return;
    this.invalidateCallbacks.forEach((cb) => cb());
  }

  public subscribeChapter(listener: ChapterListener): () => void {
    this.chapterListeners.add(listener);
    return () => this.chapterListeners.delete(listener);
  }

  public setChapter(index: number): void {
    const clamped = Math.max(0, Math.min(5, index));
    if (this.currentChapter !== clamped) {
      this.currentChapter = clamped;
      this.chapterListeners.forEach((fn) => fn(clamped));
    }
  }

  public updatePointerTarget(xOrClientX: number, yOrClientY: number, width?: number, height?: number): void {
    if (width !== undefined && height !== undefined) {
      this.pointer.targetX = (xOrClientX / (width || 1)) * 2 - 1;
      this.pointer.targetY = -(yOrClientY / (height || 1)) * 2 + 1;
    } else {
      this.pointer.targetX = xOrClientX;
      this.pointer.targetY = yOrClientY;
    }
    this.isPointerMoving = true;
    this.pointerRestFrames = 0;
  }

  /**
   * Called once per GSAP ticker frame.
   * Advances both:
   * 1. SCROLL LAYER: glides toward targetScrollProgress using frame-rate-independent damping:
   *    damp(a, b, k, dt) = a + (b - a) * (1 - exp(-k * dt)) with k = 4.0
   * 2. IDLE LAYER: uTime advances continuously via dtSeconds, independent of scroll.
   * 3. POINTER LAYER: exponential damping with k = 8.0
   */
  public tick(dtSeconds: number): boolean {
    if (!this.isVisible) return false;

    // Damp scroll progress toward target
    const dampK = 4.0;
    const scrollFactor = 1 - Math.exp(-dampK * dtSeconds);
    if (this.isMotionOn) {
      this.scrollProgress += (this.targetScrollProgress - this.scrollProgress) * scrollFactor;
      this.time += dtSeconds;
    } else {
      this.scrollProgress = this.targetScrollProgress;
    }

    // Damp pointer
    const pointerK = 8.0;
    const factor = 1 - Math.exp(-pointerK * dtSeconds);

    const prevX = this.pointer.currentX;
    const prevY = this.pointer.currentY;

    if (this.isMotionOn) {
      this.pointer.currentX += (this.pointer.targetX - this.pointer.currentX) * factor;
      this.pointer.currentY += (this.pointer.targetY - this.pointer.currentY) * factor;
    } else {
      this.pointer.currentX = 0;
      this.pointer.currentY = 0;
    }

    const dx = Math.abs(this.pointer.currentX - prevX);
    const dy = Math.abs(this.pointer.currentY - prevY);
    const isMoving = dx > 0.0001 || dy > 0.0001;

    if (!isMoving) {
      this.pointerRestFrames++;
      if (this.pointerRestFrames > 10) {
        this.isPointerMoving = false;
      }
    }

    return isMoving || this.isPointerMoving;
  }
}

export const cinematicState = new CinematicStateManager();
