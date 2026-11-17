/**
 * src/components/cinematic/3d/CinematicCanvas.tsx
 * ───────────────────────────────────────────────
 * Optimized, on-demand 3D Canvas hosting the ZEROLEAK Constellation.
 * Driven strictly from the GSAP ticker.
 */

import React, { useRef, useMemo, useEffect, useState } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { EffectComposer, Bloom } from '@react-three/postprocessing';
import { PerformanceMonitor, AdaptiveDpr, Preload } from '@react-three/drei';
import Stats from 'stats-gl';
import { useCanRun3D } from '@/hooks/useCanRun3D';
import { cinematicState } from '@/lib/cinematicState';
import { Constellation } from '@/components/three-d/Constellation';

// -------------------------------------------------------------
// R3F DEMAND CONTROLLER & STATS-GL DEBUG
// -------------------------------------------------------------
function DemandAndDebugController({ onWarmup }: { onWarmup?: () => void }) {
  const { invalidate, gl } = useThree();
  const warmupCountRef = useRef(0);

  // Hook R3F invalidate to cinematicState (ONE LOOP from GSAP ticker)
  useEffect(() => {
    return cinematicState.registerInvalidate(invalidate);
  }, [invalidate]);

  // Render initial warm-up frames invisibly
  useEffect(() => {
    const warmFrames = () => {
      if (warmupCountRef.current < 4) {
        warmupCountRef.current++;
        invalidate();
        requestAnimationFrame(warmFrames);
      } else {
        onWarmup?.();
      }
    };
    warmFrames();
  }, [invalidate, onWarmup]);

  // stats-gl integration behind ?debug=1
  useEffect(() => {
    if (typeof window === 'undefined' || !window.location.search.includes('debug=1')) return;

    let stats: any;
    try {
      stats = new Stats({
        trackGPU: true,
        logsPerSecond: 10,
        samplesGraph: 10,
        precision: 1,
        horizontal: true,
      });
      stats.init(gl.domElement);
      document.body.appendChild(stats.dom);
      stats.dom.style.position = 'fixed';
      stats.dom.style.bottom = '70px';
      stats.dom.style.left = '20px';
      stats.dom.style.zIndex = '99999';
      (window as any).__statsGL = stats;
    } catch (e) {
      console.warn('stats-gl initialization failed:', e);
    }

    return () => {
      if (stats?.dom && stats.dom.parentNode) {
        stats.dom.parentNode.removeChild(stats.dom);
      }
      delete (window as any).__statsGL;
    };
  }, [gl]);

  useFrame(() => {
    // If debug=1 is active, update stats
    if (typeof window !== 'undefined' && (window as any).__statsGL) {
      (window as any).__statsGL.update();
    }
  });

  return null;
}

// -------------------------------------------------------------
// SCENE GRAPH (Hosts Constellation + subtle bloom)
// -------------------------------------------------------------
function SceneGraph({ onWarmup }: { onWarmup?: () => void }) {
  const isMobile = useMemo(() => {
    if (typeof window === 'undefined') return false;
    return window.innerWidth < 768 || /Mobi|Android|iPhone/i.test(navigator.userAgent);
  }, []);

  return (
    <>
      <ambientLight intensity={0.5} />
      <directionalLight position={[6, 8, 5]} intensity={1.8} color="#8fdcff" />
      <directionalLight position={[-6, -4, -4]} intensity={1.2} color="#0a1f3d" />
      <pointLight position={[0, 1, 4.5]} intensity={2.0} color="#37d3fc" distance={15} />

      {/* Procedural Biomimetic Constellation across all 6 chapters */}
      <Constellation />

      {/* Bloom subtle at half resolution (intensity 0.45 to 0.55, threshold high 0.75), disabled on mobile */}
      {!isMobile && (
        <EffectComposer enableNormalPass={false} multisampling={0}>
          <Bloom
            luminanceThreshold={0.75}
            luminanceSmoothing={0.25}
            intensity={0.5}
            mipmapBlur
            resolutionScale={0.5}
          />
        </EffectComposer>
      )}

      <DemandAndDebugController onWarmup={onWarmup} />
      <Preload all />
    </>
  );
}

// -------------------------------------------------------------
// EXPORTED CINEMATIC CANVAS (Optimized, On-Demand, Low Budget)
// -------------------------------------------------------------
export interface CinematicCanvasProps {
  onWarmup?: () => void;
}

export const CinematicCanvas: React.FC<CinematicCanvasProps> = ({ onWarmup }) => {
  const canRun3D = useCanRun3D();
  const isMobile =
    typeof window !== 'undefined' &&
    (window.innerWidth < 768 || /Mobi|Android|iPhone/i.test(navigator.userAgent));
  const [dpr, setDpr] = useState(isMobile ? 1.0 : 1.25);
  const containerRef = useRef<HTMLDivElement>(null);

  // Pause rendering when hero is offscreen or tab is hidden
  useEffect(() => {
    const handleVisibility = () => {
      cinematicState.isVisible = document.visibilityState === 'visible';
      if (cinematicState.isVisible && cinematicState.isMotionOn) {
        cinematicState.invalidate();
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);

    let observer: IntersectionObserver | null = null;
    if (containerRef.current) {
      observer = new IntersectionObserver(([entry]) => {
        cinematicState.isVisible =
          entry.isIntersecting && document.visibilityState === 'visible';
        if (cinematicState.isVisible && cinematicState.isMotionOn) {
          cinematicState.invalidate();
        }
      });
      observer.observe(containerRef.current);
    }

    return () => {
      document.removeEventListener('visibilitychange', handleVisibility);
      observer?.disconnect();
    };
  }, []);

  if (!canRun3D) {
    return (
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden bg-midnight-cyber flex items-center justify-center contain-paint">
        <div className="w-52 h-52 rounded-2xl border border-[#37d3fc]/70 bg-[#37d3fc]/10 shadow-[0_0_8px_rgba(55,211,252,0.4)] backdrop-blur-md rotate-12 flex items-center justify-center -mt-24">
          <div className="w-36 h-36 rounded-xl border border-[#37d3fc]/50 bg-[#050a1c]/80 flex items-center justify-center -rotate-6">
            <span className="font-ui text-xs font-bold tracking-widest text-[#37d3fc]">
              ZEROLEAK VAULT
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 pointer-events-none z-0 select-none overflow-hidden bg-midnight-cyber contain-paint touch-none"
    >
      <Canvas
        camera={{ position: [0, 0.4, 7.2], fov: 45 }}
        dpr={dpr}
        frameloop="demand"
        gl={{
          antialias: false,
          alpha: true,
          powerPreference: 'high-performance',
          stencil: false,
          depth: true,
        }}
      >
        <PerformanceMonitor
          onDecline={() => setDpr(isMobile ? 0.85 : 1.0)}
          onIncline={() => setDpr(isMobile ? 1.15 : 1.5)}
        >
          <AdaptiveDpr pixelated />
          <fog attach="fog" args={['#020108', 6, 32]} />
          <SceneGraph onWarmup={onWarmup} />
        </PerformanceMonitor>
      </Canvas>
    </div>
  );
};

export default CinematicCanvas;
