/**
 * src/components/three-d/Constellation.tsx
 * ───────────────────────────────────────
 * Placeholder Constellation 3D Scene for ZEROLEAK AI.
 * Replaces the chunky glowing cube with a pristine, lightweight biomimetic constellation.
 *
 * Fully procedural:
 *  - 4,000 THREE.Points with soft round sprites drawn in the shader (zero texture files)
 *  - 16 glass pills (<PERSON_1>, <AADHAAR_1>...) with translucent glass, 1px cyan borders
 *  - 1 thin additive ribbon line passing through the chips along a smooth spline
 *  - Exactly one chip at a time glows warm saffron (#ff9a3d) cycling every few seconds
 *  - Text Safe Zone: chips scale down 40%, push back in depth, cut opacity to <=25%, particles fade
 *  - Two layers of motion:
 *      1. SCROLL layer: glides toward target with frame-rate-independent damping
 *      2. IDLE layer: uTime breathing, drift, chip float, particle flow, camera sway
 *  - Zero per-frame allocations (Vector3, Matrix4, Color hoisted to module scope)
 *  - Mobile budget (<768px): 1,500 particles, 8 chips
 */

import React, { useRef, useMemo, useEffect } from 'react';
import { useFrame, useThree } from '@react-three/fiber';
import * as THREE from 'three';
import { cinematicState } from '@/lib/cinematicState';

// -------------------------------------------------------------
// HOISTED SCRATCH OBJECTS (Zero allocation in loops)
// -------------------------------------------------------------
const _vPos = new THREE.Vector3();
const _vTarget = new THREE.Vector3();
const _vLook = new THREE.Vector3(0, 0.1, 0);
const _vCam = new THREE.Vector3();
const _vScan = new THREE.Vector3();

// -------------------------------------------------------------
// CHIP DATA (16 Enterprise PII tokens & raw text pairs)
// -------------------------------------------------------------
export interface ChipDef {
  id: number;
  token: string;
  raw: string;
}

export const CHIPS_ALL: ChipDef[] = [
  { id: 0, token: '<PERSON_1>', raw: 'Aarav Sharma' },
  { id: 1, token: '<AADHAAR_1>', raw: '4932 8812 0019' },
  { id: 2, token: '<PAN_1>', raw: 'ABCDE1234F' },
  { id: 3, token: '<GSTIN_1>', raw: '27AAACG0123M1Z9' },
  { id: 4, token: '<PHONE_1>', raw: '+91 98765 43210' },
  { id: 5, token: '<EMAIL_1>', raw: 'priya.s@corp.in' },
  { id: 6, token: '<ADDRESS_1>', raw: 'Flat 402, Mumbai' },
  { id: 7, token: '<PASSPORT_1>', raw: 'T8921094' },
  { id: 8, token: '<VOTER_ID_1>', raw: 'XYZ9876543' },
  { id: 9, token: '<DOB_1>', raw: '14/08/1992' },
  { id: 10, token: '<PHONE_2>', raw: '+91 91234 56789' },
  { id: 11, token: '<EMAIL_2>', raw: 'rahul@fin.co' },
  { id: 12, token: '<CARD_1>', raw: '4532 **** **** 9012' },
  { id: 13, token: '<LICENSE_1>', raw: 'DL-0420110012345' },
  { id: 14, token: '<IP_ADDR_1>', raw: '192.168.1.104' },
  { id: 15, token: '<BANK_ACC_1>', raw: 'SBIN0001234' },
];

// Helper to draw a rounded rectangle
function drawRoundedRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  w: number,
  h: number,
  r: number
) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.arcTo(x + w, y, x + w, y + r, r);
  ctx.lineTo(x + w, y + h - r);
  ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
  ctx.lineTo(x + r, y + h);
  ctx.arcTo(x, y + h, x, y + h - r, r);
  ctx.lineTo(x, y + r);
  ctx.arcTo(x, y, x + r, y, r);
  ctx.closePath();
}

// Generate high-DPI canvas texture for a glass pill chip
function createPillTexture(
  label: string,
  variant: 'ice' | 'saffron' | 'raw'
): THREE.CanvasTexture {
  const canvas = document.createElement('canvas');
  canvas.width = 384;
  canvas.height = 96;
  const ctx = canvas.getContext('2d');
  if (!ctx) return new THREE.CanvasTexture(canvas);

  const w = 384;
  const h = 96;
  const r = 22;
  const pad = 6;

  ctx.clearRect(0, 0, w, h);

  // 1. Translucent Fill (~10% white / subtle tint)
  drawRoundedRect(ctx, pad, pad, w - pad * 2, h - pad * 2, r);
  if (variant === 'saffron') {
    ctx.fillStyle = 'rgba(255, 154, 61, 0.14)';
  } else if (variant === 'raw') {
    ctx.fillStyle = 'rgba(239, 68, 68, 0.12)';
  } else {
    ctx.fillStyle = 'rgba(255, 255, 255, 0.08)';
  }
  ctx.fill();

  // 2. 1px Crisp Border (~30% cyan or saffron)
  ctx.lineWidth = 2.5;
  if (variant === 'saffron') {
    ctx.strokeStyle = 'rgba(255, 154, 61, 0.85)';
    ctx.shadowColor = 'rgba(255, 154, 61, 0.6)';
    ctx.shadowBlur = 10;
  } else if (variant === 'raw') {
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.75)';
    ctx.shadowColor = 'rgba(239, 68, 68, 0.5)';
    ctx.shadowBlur = 8;
  } else {
    ctx.strokeStyle = 'rgba(55, 211, 252, 0.38)';
    ctx.shadowColor = 'rgba(55, 211, 252, 0.4)';
    ctx.shadowBlur = 8;
  }
  ctx.stroke();

  // Reset shadow for crisp text
  ctx.shadowBlur = 0;

  // 3. Monospace Label Text
  ctx.font = '600 32px "JetBrains Mono", monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  if (variant === 'saffron') {
    ctx.fillStyle = '#ff9a3d';
  } else if (variant === 'raw') {
    ctx.fillStyle = '#fca5a5';
  } else {
    ctx.fillStyle = '#d5ddfd';
  }
  ctx.fillText(label, w / 2, h / 2 + 1);

  // 4. Subtle status dot on left
  ctx.beginPath();
  ctx.arc(36, h / 2, 4.5, 0, Math.PI * 2);
  if (variant === 'saffron') {
    ctx.fillStyle = '#ff9a3d';
  } else if (variant === 'raw') {
    ctx.fillStyle = '#ef4444';
  } else {
    ctx.fillStyle = '#37d3fc';
  }
  ctx.fill();

  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;
  texture.magFilter = THREE.LinearFilter;
  texture.needsUpdate = true;
  return texture;
}

// -------------------------------------------------------------
// PARTICLE SHADER MATERIAL (Zero texture files, additive, soft round sprites)
// -------------------------------------------------------------
const ParticleShader = {
  vertexShader: `
    uniform float uTime;
    uniform float uDpr;
    uniform vec4 uSafeZone; // xMin, yMin, xMax, yMax
    
    attribute float aSeed;
    attribute float aLayer;
    attribute float aSize;

    varying float vAlpha;
    varying vec3 vColor;

    void main() {
      vec3 pos = position;
      
      // Multi-speed depth layer flow (3 distinct speeds)
      float speed = (aLayer + 1.0) * 0.10;
      pos.x += sin(uTime * speed + aSeed * 6.2831) * 0.35;
      pos.y += cos(uTime * (speed * 0.85) + aSeed * 3.1415) * 0.35;
      pos.z += sin(uTime * 0.06 + aSeed * 6.2831) * 0.25;

      // Per-particle twinkle
      float twinkle = 0.5 + 0.5 * sin(uTime * (1.6 + aSeed * 2.2) + aSeed * 6.2831);

      // Color gradient: ice blue #8fdcff to cyan #37d3fc
      vec3 colIce = vec3(0.56, 0.86, 1.0);
      vec3 colCyan = vec3(0.216, 0.827, 0.988);
      vColor = mix(colIce, colCyan, aSeed);

      // Text Safe Zone fade (smooth radial / box mask)
      float dx = abs(pos.x) / uSafeZone.z;
      float dy = abs(pos.y) / uSafeZone.w;
      float distToSafe = max(dx, dy);
      float safeFade = smoothstep(0.45, 1.15, distToSafe);

      // Base opacity: 0.15 to 0.50
      float baseOpacity = 0.16 + 0.34 * aSeed;
      vAlpha = baseOpacity * safeFade * (0.65 + 0.35 * twinkle);

      vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
      gl_Position = projectionMatrix * mvPosition;

      // Point size in px (1 to 2.5px), scaled by layer and distance
      gl_PointSize = (aSize * uDpr * (1.0 + 0.35 * aLayer)) * (16.0 / -mvPosition.z);
    }
  `,
  fragmentShader: `
    varying float vAlpha;
    varying vec3 vColor;

    void main() {
      // Procedural soft round sprite (no texture files)
      vec2 coord = gl_PointCoord - vec2(0.5);
      float dist = length(coord);
      if (dist > 0.5) discard;

      // Soft circular falloff
      float shape = smoothstep(0.5, 0.04, dist);
      gl_FragColor = vec4(vColor, vAlpha * shape);
    }
  `,
};

// -------------------------------------------------------------
// CONSTELLATION COMPONENT
// -------------------------------------------------------------
export const Constellation: React.FC = () => {
  const { gl, viewport } = useThree();
  const isMobile = typeof window !== 'undefined' && window.innerWidth < 768;
  const chipCount = isMobile ? 8 : 16;
  const particleCount = isMobile ? 1500 : 4000;

  const pointsRef = useRef<THREE.Points>(null);
  const particleMaterialRef = useRef<THREE.ShaderMaterial>(null);
  const groupRef = useRef<THREE.Group>(null);
  const lineRef = useRef<THREE.Line>(null);
  const scanLineRef = useRef<THREE.Mesh>(null);
  const chipsMeshesRef = useRef<(THREE.Mesh | null)[]>([]);

  // 1. Generate & Cache Pill Textures (Zero re-allocations)
  const textures = useMemo(() => {
    const list: {
      ice: THREE.CanvasTexture;
      saffron: THREE.CanvasTexture;
      raw: THREE.CanvasTexture;
    }[] = [];

    const chips = CHIPS_ALL.slice(0, chipCount);
    for (const chip of chips) {
      list.push({
        ice: createPillTexture(chip.token, 'ice'),
        saffron: createPillTexture(chip.token, 'saffron'),
        raw: createPillTexture(chip.raw, 'raw'),
      });
    }
    return list;
  }, [chipCount]);

  // Cleanup textures on unmount
  useEffect(() => {
    return () => {
      textures.forEach((t) => {
        t.ice.dispose();
        t.saffron.dispose();
        t.raw.dispose();
      });
    };
  }, [textures]);

  // 2. Build Procedural Particle System (4,000 points, 3 depth layers)
  const { particleGeometry, particleMaterial } = useMemo(() => {
    const positions = new Float32Array(particleCount * 3);
    const seeds = new Float32Array(particleCount);
    const layers = new Float32Array(particleCount);
    const sizes = new Float32Array(particleCount);

    for (let i = 0; i < particleCount; i++) {
      // Distribute in a wide frustum volume
      positions[i * 3 + 0] = (Math.random() - 0.5) * 22;
      positions[i * 3 + 1] = (Math.random() - 0.5) * 14;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 12 - 2;

      seeds[i] = Math.random();
      layers[i] = i % 3; // 3 depth layers
      sizes[i] = 1.0 + Math.random() * 1.5; // 1 to 2.5px
    }

    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geo.setAttribute('aSeed', new THREE.BufferAttribute(seeds, 1));
    geo.setAttribute('aLayer', new THREE.BufferAttribute(layers, 1));
    geo.setAttribute('aSize', new THREE.BufferAttribute(sizes, 1));

    const mat = new THREE.ShaderMaterial({
      vertexShader: ParticleShader.vertexShader,
      fragmentShader: ParticleShader.fragmentShader,
      uniforms: {
        uTime: { value: 0 },
        uDpr: { value: gl.getPixelRatio() },
        uSafeZone: { value: new THREE.Vector4(-3.4, -2.1, 3.4, 2.1) },
      },
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });

    return { particleGeometry: geo, particleMaterial: mat };
  }, [particleCount, gl]);

  // Cleanup particles
  useEffect(() => {
    return () => {
      particleGeometry.dispose();
      particleMaterial.dispose();
    };
  }, [particleGeometry, particleMaterial]);

  // 3. Shared Pill Geometry & Materials
  const pillGeometry = useMemo(() => new THREE.PlaneGeometry(1.6, 0.4), []);
  useEffect(() => {
    return () => pillGeometry.dispose();
  }, [pillGeometry]);

  // 4. Spline Ribbon Line (Connecting chips with thin additive line)
  const { lineGeometry, lineMaterial } = useMemo(() => {
    const pts: THREE.Vector3[] = [];
    const numPoints = 80;
    for (let i = 0; i < numPoints; i++) {
      pts.push(new THREE.Vector3(0, 0, 0));
    }
    const geo = new THREE.BufferGeometry().setFromPoints(pts);
    const mat = new THREE.LineBasicMaterial({
      color: 0x37d3fc,
      transparent: true,
      opacity: 0.28,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    return { lineGeometry: geo, lineMaterial: mat };
  }, []);

  const lineMesh = useMemo(
    () => new THREE.Line(lineGeometry, lineMaterial),
    [lineGeometry, lineMaterial]
  );

  useEffect(() => {
    return () => {
      lineGeometry.dispose();
      lineMaterial.dispose();
    };
  }, [lineGeometry, lineMaterial]);

  // 5. Scan Line for Chapter 2 DETECT
  const scanLineGeometry = useMemo(() => new THREE.PlaneGeometry(0.04, 12), []);
  const scanLineMaterial = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: 0x37d3fc,
        transparent: true,
        opacity: 0.45,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    []
  );
  useEffect(() => {
    return () => {
      scanLineGeometry.dispose();
      scanLineMaterial.dispose();
    };
  }, [scanLineGeometry, scanLineMaterial]);

  // -------------------------------------------------------------
  // ANIMATION LOOP (Single GSAP Ticker, Zero Allocations)
  // -------------------------------------------------------------
  useFrame((state, delta) => {
    if (!cinematicState.isVisible) return;

    // Time & Progress from state (SCROLL + IDLE LAYERS)
    const time = cinematicState.time;
    const isMotionOn = cinematicState.isMotionOn;
    const progress = cinematicState.scrollProgress; // continuous 0.0 to 1.0
    const chapterVal = progress * 5; // 0.0 to 5.0

    // Update particle uniforms
    if (particleMaterialRef.current) {
      particleMaterialRef.current.uniforms.uTime.value = time;
    }

    // Camera Sway (0.5 to 1.0s subtle floating sway)
    const ptr = cinematicState.pointer;
    if (isMotionOn) {
      const swayX = Math.sin(time * 0.8) * 0.12 + ptr.currentX * 0.45;
      const swayY = Math.cos(time * 0.6) * 0.08 - ptr.currentY * 0.35;
      _vCam.set(swayX, 0.4 + swayY, 7.2);
      state.camera.position.lerp(_vCam, 0.08);
      state.camera.lookAt(_vLook);
    }

    // Slow group drift and breathing (0.05 to 0.15 rad/s)
    if (groupRef.current && isMotionOn) {
      groupRef.current.rotation.z = Math.sin(time * 0.08) * 0.04;
      groupRef.current.rotation.y = Math.cos(time * 0.06) * 0.05;
      groupRef.current.position.y = Math.sin(time * 0.12) * 0.06;
    }

    // Saffron Accent Cycling (cycles every 3.5 seconds)
    const activeAccentIdx = isMotionOn ? Math.floor(time / 3.5) % chipCount : 1;

    // Scan Line Sweep for Chapter 2 DETECT (sweeps across X = -6 to +6)
    const scanPeriod = 2.8;
    const scanPhase = (time % scanPeriod) / scanPeriod;
    const scanX = -6.5 + scanPhase * 13.0;
    if (scanLineRef.current) {
      scanLineRef.current.position.x = scanX;
      // Active primarily in chapter 1 (DETECT)
      const detectWeight = Math.max(0, 1.0 - Math.abs(chapterVal - 1.0));
      scanLineMaterial.opacity = 0.5 * detectWeight;
      scanLineRef.current.visible = detectWeight > 0.05;
    }

    // Spline line positions array
    const splinePoints: THREE.Vector3[] = [];

    // ---------------------------------------------------------
    // COMPUTE PER-CHAPTER CHIP POSITIONS & EMPHASIS
    // ---------------------------------------------------------
    for (let i = 0; i < chipCount; i++) {
      const mesh = chipsMeshesRef.current[i];
      if (!mesh) continue;

      const angle = (i / chipCount) * Math.PI * 2;
      const isAccent = i === activeAccentIdx;

      // Base layout 01: GATEWAY (Wide slow elliptical orbit around empty center)
      const orbitRx = isMobile ? 3.4 : 5.8;
      const orbitRy = isMobile ? 2.6 : 3.2;
      const orbitAngle = angle + (isMotionOn ? time * 0.07 : 0);
      const x0 = Math.cos(orbitAngle) * orbitRx;
      const y0 = Math.sin(orbitAngle) * orbitRy;
      const z0 = Math.sin(orbitAngle * 2.0) * 0.4;

      // Base layout 02: DETECT (Analyzed constellation across periphery)
      const col = i % 4;
      const row = Math.floor(i / 4);
      const x1 = (col - 1.5) * 3.2;
      const y1 = (row - 1.5) * 1.8 + (i % 2 === 0 ? 0.3 : -0.3);
      const z1 = Math.cos(angle * 3) * 0.5;

      // Base layout 03: MASK (Framing left/right edges while raw values dissolve)
      const side = i % 2 === 0 ? -1 : 1;
      const x2 = side * (isMobile ? 3.0 : 5.2) + Math.sin(angle * 4) * 0.4;
      const y2 = ((i % 8) - 3.5) * 0.75;
      const z2 = Math.sin(angle) * 0.6;

      // Base layout 04: FORWARD (Chips streaming rightward along line)
      const streamProgress = isMotionOn ? (time * 1.6 + i * 1.1) % 18.0 - 9.0 : (i - 8) * 1.0;
      const x3 = streamProgress;
      const y3 = Math.sin(streamProgress * 0.4 + i) * 1.4 + (i % 2 === 0 ? 1.6 : -1.6);
      const z3 = Math.cos(streamProgress * 0.5) * 0.6;

      // Base layout 05: REINSERT (Chips streaming back and settling)
      const returnProgress = isMotionOn ? (9.0 - (time * 1.6 + i * 1.1) % 18.0) : (8 - i) * 1.0;
      const x4 = returnProgress;
      const y4 = Math.cos(returnProgress * 0.4 + i) * 1.4 + (i % 2 === 0 ? 1.6 : -1.6);
      const z4 = Math.sin(returnProgress * 0.5) * 0.6;

      // Base layout 06: PROOF (Architectural perimeter grid behind metrics)
      const gridX = i < 4 ? (i - 1.5) * 3.2 : i < 8 ? (isMobile ? 2.9 : 5.4) : i < 12 ? (i - 9.5) * -3.2 : (isMobile ? -2.9 : -5.4);
      const gridY = i < 4 ? 2.8 : i < 8 ? (i - 5.5) * 1.3 : i < 12 ? -2.7 : (i - 13.5) * 1.3;
      const x5 = gridX;
      const y5 = gridY;
      const z5 = -0.5;

      // Blend positions across the 6 chapters based on continuous chapterVal
      let targetX = x0;
      let targetY = y0;
      let targetZ = z0;

      if (chapterVal < 1.0) {
        const t = chapterVal;
        targetX = THREE.MathUtils.lerp(x0, x1, t);
        targetY = THREE.MathUtils.lerp(y0, y1, t);
        targetZ = THREE.MathUtils.lerp(z0, z1, t);
      } else if (chapterVal < 2.0) {
        const t = chapterVal - 1.0;
        targetX = THREE.MathUtils.lerp(x1, x2, t);
        targetY = THREE.MathUtils.lerp(y1, y2, t);
        targetZ = THREE.MathUtils.lerp(z1, z2, t);
      } else if (chapterVal < 3.0) {
        const t = chapterVal - 2.0;
        targetX = THREE.MathUtils.lerp(x2, x3, t);
        targetY = THREE.MathUtils.lerp(y2, y3, t);
        targetZ = THREE.MathUtils.lerp(z2, z3, t);
      } else if (chapterVal < 4.0) {
        const t = chapterVal - 3.0;
        targetX = THREE.MathUtils.lerp(x3, x4, t);
        targetY = THREE.MathUtils.lerp(y3, y4, t);
        targetZ = THREE.MathUtils.lerp(z3, z4, t);
      } else {
        const t = Math.min(1.0, chapterVal - 4.0);
        targetX = THREE.MathUtils.lerp(x4, x5, t);
        targetY = THREE.MathUtils.lerp(y4, y5, t);
        targetZ = THREE.MathUtils.lerp(z4, z5, t);
      }

      // Idle float offset (small sine offsets with different phases)
      if (isMotionOn) {
        targetX += Math.sin(time * 0.7 + i * 0.8) * 0.08;
        targetY += Math.cos(time * 0.85 + i * 1.2) * 0.08;
      }

      // -------------------------------------------------------
      // TEXT SAFE ZONE: Central 60% width by vertical band
      // Inside it: scale chips down 40%, push back in depth, cut opacity to <= 25%
      // -------------------------------------------------------
      const safeRadiusX = isMobile ? 2.4 : 3.4;
      const safeRadiusY = isMobile ? 1.8 : 2.1;
      const normDistX = Math.abs(targetX) / safeRadiusX;
      const normDistY = Math.abs(targetY) / safeRadiusY;
      const safeDist = Math.max(normDistX, normDistY);
      const safeFactor = THREE.MathUtils.clamp((safeDist - 0.4) / 0.6, 0.0, 1.0);

      // Safe zone depth push & scale
      const chipScale = 0.6 + 0.4 * safeFactor; // down to 0.6 (40% down)
      const chipZ = targetZ - (1.0 - safeFactor) * 2.8;

      mesh.position.set(targetX, targetY, chipZ);
      mesh.scale.set(chipScale, chipScale, 1.0);

      // Chapter 2 DETECT scan line brightening
      let scanBoost = 0;
      if (Math.abs(chapterVal - 1.0) < 0.6) {
        const distToScan = Math.abs(targetX - scanX);
        if (distToScan < 1.4) {
          scanBoost = (1.4 - distToScan) / 1.4;
        }
      }

      // Chapter 3 MASK raw text dissolve into chips
      const maskWeight = Math.max(0, 1.0 - Math.abs(chapterVal - 2.0));
      const showRaw = maskWeight > 0.4 && (time + i) % 4.0 < 1.6;

      // Select active texture & material
      const mat = mesh.material as THREE.MeshBasicMaterial;
      if (isAccent) {
        mat.map = textures[i].saffron;
      } else if (showRaw) {
        mat.map = textures[i].raw;
      } else {
        mat.map = textures[i].ice;
      }

      // Safe zone opacity: at most 0.25 inside, up to 0.95 outside
      const baseOpacity = isAccent ? 0.95 : 0.82;
      const targetOpacity = (0.22 + 0.78 * safeFactor) * (baseOpacity + scanBoost * 0.25);
      mat.opacity = Math.min(1.0, targetOpacity);
      mat.needsUpdate = false;

      splinePoints.push(mesh.position);
    }

    // Update Ribbon Spline Line passing through chips
    if (lineRef.current && splinePoints.length >= 4) {
      try {
        const curve = new THREE.CatmullRomCurve3(splinePoints, true, 'centripetal');
        const sampleCount = 64;
        const sampled = curve.getPoints(sampleCount);
        const posAttr = lineGeometry.attributes.position as THREE.BufferAttribute;
        for (let j = 0; j < sampled.length && j < posAttr.count; j++) {
          posAttr.setXYZ(j, sampled[j].x, sampled[j].y, sampled[j].z - 0.1);
        }
        posAttr.needsUpdate = true;
      } catch (e) {}
    }
  });

  return (
    <group ref={groupRef}>
      {/* 1. Procedural 4,000 Points with Additive Round Sprites */}
      <points
        ref={pointsRef}
        geometry={particleGeometry}
        material={particleMaterial}
      />

      {/* 2. Thin Additive Ribbon Line Connecting Chips */}
      <primitive object={lineMesh} ref={lineRef} />

      {/* 3. Luminous Scan Line for Chapter 02 (DETECT) */}
      <mesh
        ref={scanLineRef}
        geometry={scanLineGeometry}
        material={scanLineMaterial}
        position={[0, 0, 0]}
      />

      {/* 4. 16 Glass Pill Chips */}
      {CHIPS_ALL.slice(0, chipCount).map((chip, idx) => (
        <mesh
          key={chip.id}
          ref={(el) => {
            chipsMeshesRef.current[idx] = el;
          }}
          geometry={pillGeometry}
        >
          <meshBasicMaterial
            map={textures[idx].ice}
            transparent
            depthWrite={false}
            blending={THREE.NormalBlending}
            opacity={0.85}
          />
        </mesh>
      ))}
    </group>
  );
};

export default Constellation;
