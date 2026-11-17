import React, { useEffect, useState, useRef, useCallback } from 'react';
import { SmoothScrollProvider } from '@/components/hubtown/SmoothScrollProvider';
import { CinematicLoader } from '@/components/cinematic/CinematicLoader';
import { HudFrame } from '@/components/cinematic/HudFrame';
import { CinematicHeader } from '@/components/cinematic/CinematicHeader';
import { ChapterIndex } from '@/components/cinematic/ChapterIndex';
import { HudBottomBar } from '@/components/cinematic/HudBottomBar';
import { ChapterContent } from '@/components/cinematic/ChapterContent';
import { FullscreenMenu } from '@/components/cinematic/FullscreenMenu';
import { CinematicCanvas } from '@/components/cinematic/3d/CinematicCanvas';
import { ScrollTrigger, Observer } from '@/lib/gsap';
import { cinematicState } from '@/lib/cinematicState';

export const LandingPage: React.FC = () => {
  const [currentChapter, setCurrentChapter] = useState(0);
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  // Motion ON/OFF state (initialized based on user's system preferences)
  const [isMotionOn, setIsMotionOn] = useState(() => {
    if (typeof window !== 'undefined') {
      return !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    }
    return true;
  });

  const scrollTrackRef = useRef<HTMLDivElement>(null);
  const currentChapterRef = useRef(0);

  // Sync isMotionOn to cinematicState
  useEffect(() => {
    cinematicState.isMotionOn = isMotionOn;
    cinematicState.needsStillFrame = true;
    cinematicState.invalidate();
  }, [isMotionOn]);

  // Jump smoothly to a specific chapter (0 to 5)
  const jumpToChapter = useCallback(
    (index: number) => {
      const clampedIndex = Math.max(0, Math.min(5, index));
      const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
      const targetScroll = (clampedIndex / 5) * maxScroll;

      const lenis = (window as any).__lenis;
      if (lenis && isMotionOn) {
        lenis.scrollTo(targetScroll, {
          duration: 1.0,
          easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
        });
      } else {
        window.scrollTo({
          top: targetScroll,
          behavior: isMotionOn ? 'smooth' : 'auto',
        });
      }
      currentChapterRef.current = clampedIndex;
      cinematicState.setChapter(clampedIndex);
      setCurrentChapter(clampedIndex);
    },
    [isMotionOn]
  );

  // Keyboard and GSAP Observer navigation between chapters
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Do not intercept if menu is open or active element is an input
      if (isMenuOpen) return;
      const target = e.target as HTMLElement | null;
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) return;

      if (e.key === 'ArrowDown' || e.key === 'PageDown' || (e.key === ' ' && !e.shiftKey)) {
        e.preventDefault();
        jumpToChapter(currentChapterRef.current + 1);
      } else if (e.key === 'ArrowUp' || e.key === 'PageUp' || (e.key === ' ' && e.shiftKey)) {
        e.preventDefault();
        jumpToChapter(currentChapterRef.current - 1);
      }
    };

    // GSAP Observer with sensible tolerance to smoothly retarget
    const obs = Observer.create({
      target: window,
      type: 'wheel,touch,pointer',
      tolerance: 20,
      preventDefault: false,
    });

    window.addEventListener('keydown', handleKeyDown);

    return () => {
      obs.kill();
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [currentChapter, jumpToChapter, isMenuOpen]);

  // Pointer move tracking (Zero React re-render, damped coordinates in cinematicState)
  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      const x = (e.clientX / window.innerWidth) * 2 - 1;
      const y = -(e.clientY / window.innerHeight) * 2 + 1;
      cinematicState.updatePointerTarget(x, y);
    };

    window.addEventListener('pointermove', handlePointerMove, { passive: true });
    return () => window.removeEventListener('pointermove', handlePointerMove);
  }, []);

  // GSAP ScrollTrigger setup on virtual scroll track (600vh)
  useEffect(() => {
    if (!scrollTrackRef.current) return;

    // Mobile touch normalization
    const isTouch =
      typeof window !== 'undefined' &&
      ('ontouchstart' in window || navigator.maxTouchPoints > 0);
    if (isTouch) {
      ScrollTrigger.normalizeScroll(true);
    }

    const trigger = ScrollTrigger.create({
      trigger: scrollTrackRef.current,
      start: 'top top',
      end: 'bottom bottom',
      scrub: isMotionOn ? 0.8 : 0,
      snap: isMotionOn
        ? {
            snapTo: [0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
            duration: { min: 0.2, max: 0.7 },
            ease: 'power2.inOut',
          }
        : undefined,
      onUpdate: (self) => {
        const p = self.progress;
        cinematicState.targetScrollProgress = p;
        const activeIdx = Math.min(5, Math.max(0, Math.round(p * 5)));
        if (activeIdx !== currentChapterRef.current) {
          currentChapterRef.current = activeIdx;
          cinematicState.setChapter(activeIdx);
          setCurrentChapter(activeIdx);
        }
      },
    });

    // Single debounced ResizeObserver to refresh ScrollTrigger cleanly
    let rAFId: number | null = null;
    const ro = new ResizeObserver(() => {
      if (rAFId) cancelAnimationFrame(rAFId);
      rAFId = requestAnimationFrame(() => {
        ScrollTrigger.refresh();
      });
    });
    ro.observe(document.documentElement);

    ScrollTrigger.refresh();

    return () => {
      if (rAFId) cancelAnimationFrame(rAFId);
      ro.disconnect();
      trigger.kill();
    };
  }, [isMotionOn]);

  return (
    <SmoothScrollProvider>
      {/* 1. Numerical 0% -> 100% Loader with Split Shutter Reveal & Warmup */}
      <CinematicLoader />

      {/* 2. Fixed Full-Viewport Stage (dvh for mobile chrome tolerance + contain: layout paint) */}
      <main className="fixed inset-0 w-full h-[100dvh] overflow-hidden select-none bg-midnight-cyber contain-layout contain-paint">
        {/* 3D WebGL Monolith & Procedural Stations */}
        <CinematicCanvas />

        {/* HUD Inset Border with Chamfered Top-Right Corner */}
        <HudFrame />

        {/* Global HUD Header (Wordmark, Nav, Chamfered Buttons) */}
        <CinematicHeader
          onOpenMenu={() => setIsMenuOpen(true)}
          onJumpToChapter={jumpToChapter}
        />

        {/* Left Vertical Chapter Index */}
        <ChapterIndex
          currentChapter={currentChapter}
          onSelectChapter={jumpToChapter}
        />

        {/* Central Chapter Headline Scramble, Copy, and CTA */}
        <ChapterContent
          currentChapter={currentChapter}
          isMotionOn={isMotionOn}
        />

        {/* Bottom HUD Bar (Motion Toggle, Prev/Next, Live Demo Link) */}
        <HudBottomBar
          currentChapter={currentChapter}
          isMotionOn={isMotionOn}
          onToggleMotion={() => setIsMotionOn((prev) => !prev)}
          onPrevChapter={() => jumpToChapter(currentChapter - 1)}
          onNextChapter={() => jumpToChapter(currentChapter + 1)}
        />

        {/* Fullscreen Architectural Menu Overlay */}
        <FullscreenMenu
          isOpen={isMenuOpen}
          onClose={() => setIsMenuOpen(false)}
          onSelectChapter={jumpToChapter}
        />
      </main>

      {/* 3. 600vh Virtual Scroll Track (Enables smooth wheel & touch scrolling through 6 chapters) */}
      <div
        ref={scrollTrackRef}
        className="relative w-full h-[600vh] pointer-events-none touch-pan-y"
        aria-hidden="true"
      />
    </SmoothScrollProvider>
  );
};

export default LandingPage;
