import React, { useEffect, useState, useRef } from 'react';
import gsap from 'gsap';

interface CinematicLoaderProps {
  onComplete?: () => void;
}

export const CinematicLoader: React.FC<CinematicLoaderProps> = ({ onComplete }) => {
  const [progress, setProgress] = useState(0);
  const [isDone, setIsDone] = useState(false);
  const [statusText, setStatusText] = useState('Loading scene');

  const topShutterRef = useRef<HTMLDivElement>(null);
  const bottomShutterRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const progressRef = useRef(0);

  useEffect(() => {
    let isCancelled = false;
    let intervalId: any = null;

    // Smooth ticker for visual progress counter
    intervalId = setInterval(() => {
      if (progressRef.current < 90) {
        progressRef.current = Math.min(90, progressRef.current + Math.floor(Math.random() * 8) + 4);
        setProgress(progressRef.current);
      }
    }, 40);

    // Warm-up pipeline: fonts ready, images decode, 3 rAF frames rendered
    const warmup = async () => {
      try {
        if (typeof document !== 'undefined' && 'fonts' in document) {
          await document.fonts.ready;
        }

        if (typeof document !== 'undefined') {
          const imgs = Array.from(document.querySelectorAll('img'));
          await Promise.all(imgs.map((img) => img.decode().catch(() => {})));
        }

        // Wait for 3 rAF cycles so WebGL canvas compiles shaders and uploads textures
        await new Promise<void>((resolve) => {
          let frames = 0;
          const tick = () => {
            frames++;
            if (frames >= 3) {
              resolve();
            } else {
              requestAnimationFrame(tick);
            }
          };
          requestAnimationFrame(tick);
        });
      } catch (e) {
        // Fallback gracefully on warm-up error
      }

      if (isCancelled) return;
      clearInterval(intervalId);

      // Fast-forward to 100%
      progressRef.current = 100;
      setProgress(100);
      setStatusText('Ready to explore');

      // Shutter reveal animation with power3.inOut over 0.6s
      setTimeout(() => {
        if (isCancelled) return;
        const tl = gsap.timeline({
          onComplete: () => {
            setIsDone(true);
            onComplete?.();
          },
        });

        // Fade out counter content
        tl.to(contentRef.current, {
          opacity: 0,
          duration: 0.25,
          ease: 'power2.in',
        });

        // Split shutter reveal with power3.inOut
        tl.to(
          topShutterRef.current,
          {
            yPercent: -100,
            duration: 0.6,
            ease: 'power3.inOut',
          },
          '+=0.05'
        );

        tl.to(
          bottomShutterRef.current,
          {
            yPercent: 100,
            duration: 0.6,
            ease: 'power3.inOut',
          },
          '<'
        );
      }, 150);
    };

    warmup();

    return () => {
      isCancelled = true;
      if (intervalId) clearInterval(intervalId);
    };
  }, [onComplete]);

  if (isDone) return null;

  return (
    <div className="fixed inset-0 z-50 pointer-events-auto select-none overflow-hidden">
      {/* Top Shutter */}
      <div
        ref={topShutterRef}
        className="absolute top-0 left-0 right-0 h-1/2 bg-[#020108] border-b border-[#37d3fc]/20 z-10"
      />

      {/* Bottom Shutter */}
      <div
        ref={bottomShutterRef}
        className="absolute bottom-0 left-0 right-0 h-1/2 bg-[#020108] border-t border-[#37d3fc]/20 z-10"
      />

      {/* Center Counter & Status */}
      <div
        ref={contentRef}
        className="absolute inset-0 flex flex-col items-center justify-center z-20 text-[#d5ddfd]"
      >
        <div className="flex items-baseline gap-2 font-headline text-6xl sm:text-7xl md:text-8xl font-black tracking-tight">
          <span className="text-[#37d3fc]">{progress}</span>
          <span className="text-xl sm:text-2xl text-[#94a3b8] font-ui">%</span>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <span className="w-1.5 h-1.5 bg-[#37d3fc] animate-pulse shadow-[0_0_8px_#37d3fc]" />
          <span className="font-ui text-xs tracking-[0.24em] uppercase text-[#94a3b8]">
            {statusText}
          </span>
        </div>

        {/* Progress bar track */}
        <div className="w-48 sm:w-64 h-[2px] bg-white/10 mt-6 overflow-hidden">
          <div
            className="h-full bg-[#37d3fc] transition-all duration-75 shadow-[0_0_10px_#37d3fc]"
            style={{ width: `${progress}%` }}
          />
        </div>

        <div className="mt-4 flex flex-col items-center gap-1">
          <div className="font-ui text-[11px] tracking-[0.2em] uppercase text-[#d5ddfd]/80">
            ZEROLEAK AI // ENTERPRISE DPDP GATEWAY
          </div>
          <div className="font-ui text-[9px] tracking-[0.24em] uppercase text-[#37d3fc]/70">
            PRIVACY. PROTECTED. INTELLIGENCE. UNLEASHED.
          </div>
        </div>
      </div>
    </div>
  );
};

export default CinematicLoader;
