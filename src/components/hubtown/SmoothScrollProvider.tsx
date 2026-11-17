import React, { useEffect, useRef } from 'react';
import Lenis from 'lenis';
import { gsap, ScrollTrigger } from '@/lib/gsap';
import { cinematicState } from '@/lib/cinematicState';

interface SmoothScrollProviderProps {
  children: React.ReactNode;
}

/**
 * Hubtown-grade buttery smooth inertia scroller powered by Lenis + GSAP ScrollTrigger.
 * ONE LOOP: Driven strictly from the GSAP ticker with autoRaf: false.
 * For R3F, uses frameloop="demand" and calls invalidate() from this single ticker.
 */
export const SmoothScrollProvider: React.FC<SmoothScrollProviderProps> = ({ children }) => {
  const lenisRef = useRef<Lenis | null>(null);

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia(
      '(prefers-reduced-motion: reduce)'
    ).matches;
    if (prefersReducedMotion) return;

    // Set Lenis autoRaf: false so GSAP ticker owns the single rAF loop
    const lenis = new Lenis({
      duration: 1.2,
      easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      orientation: 'vertical',
      gestureOrientation: 'vertical',
      smoothWheel: true,
      wheelMultiplier: 0.95,
      touchMultiplier: 1.4,
      autoRaf: false,
    });
    lenisRef.current = lenis;
    (window as any).__lenis = lenis;

    // Connect Lenis scroll updates to GSAP ScrollTrigger
    lenis.on('scroll', ScrollTrigger.update);

    // Single rAF ticker loop
    const updateTicker = (time: number, deltaTime: number) => {
      // 1. Update Lenis
      lenis.raf(time * 1000);

      // 2. Advance time, damp scroll progress and pointer
      cinematicState.tick(deltaTime / 1000);

      // 3. Render every frame while hero is visible and MOTION is ON.
      // Under MOTION: OFF, render one calm still frame, then pause.
      if (cinematicState.isVisible) {
        if (cinematicState.isMotionOn) {
          cinematicState.invalidate();
        } else if (cinematicState.needsStillFrame) {
          cinematicState.invalidate();
          cinematicState.needsStillFrame = false;
        }
      }
    };

    gsap.ticker.add(updateTicker);
    gsap.ticker.lagSmoothing(0);

    return () => {
      gsap.ticker.remove(updateTicker);
      lenis.destroy();
      lenisRef.current = null;
    };
  }, []);

  return <div className="smooth-scroll-wrapper">{children}</div>;
};

export default SmoothScrollProvider;
