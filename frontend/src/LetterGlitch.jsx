import { useEffect, useRef } from 'react';

const defaultGlyphs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`';

export default function LetterGlitch({
  glitchSpeed = 45,
  glitchColors = ['#00F5FF', '#8A2BE2', '#3B82F6'],
  centerVignette = true,
  outerVignette = true,
  smooth = true,
  className = ''
}) {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current, ctx = canvas.getContext('2d');
    let frame, columns = [], lastPaint = 0;
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2), rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * dpr; canvas.height = rect.height * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      columns = Array.from({ length: Math.ceil(rect.width / 15) }, () => Math.random() * rect.height);
    };
    const render = (now) => {
      frame = requestAnimationFrame(render);
      if (now - lastPaint < 1000 / glitchSpeed) return;
      lastPaint = now;
      const { width, height } = canvas.getBoundingClientRect();
      ctx.fillStyle = smooth ? 'rgba(6, 10, 15, .16)' : 'rgba(6, 10, 15, .34)'; ctx.fillRect(0, 0, width, height);
      ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, monospace';
      columns.forEach((y, index) => {
        const hot = Math.random() > .96;
        const color = glitchColors[Math.floor(Math.random() * glitchColors.length)];
        ctx.fillStyle = hot ? `${color}${smooth ? 'a8' : 'dd'}` : `${color}42`;
        ctx.fillText(defaultGlyphs[Math.floor(Math.random() * defaultGlyphs.length)], index * 15, y);
        columns[index] = y > height && Math.random() > .985 ? 0 : y + 5 + Math.random() * 11;
      });
      if (centerVignette || outerVignette) {
        const gradient = ctx.createRadialGradient(width * .5, height * .5, Math.min(width, height) * .12, width * .5, height * .5, Math.max(width, height) * .7);
        gradient.addColorStop(0, centerVignette ? 'rgba(6,10,15,.06)' : 'rgba(6,10,15,0)');
        gradient.addColorStop(outerVignette ? .72 : 1, 'rgba(6,10,15,0)');
        gradient.addColorStop(1, outerVignette ? 'rgba(6,10,15,.58)' : 'rgba(6,10,15,0)');
        ctx.fillStyle = gradient; ctx.fillRect(0, 0, width, height);
      }
    };
    resize(); frame = requestAnimationFrame(render); window.addEventListener('resize', resize);
    return () => { cancelAnimationFrame(frame); window.removeEventListener('resize', resize); };
  }, [glitchSpeed, glitchColors, centerVignette, outerVignette, smooth]);
  return <canvas ref={ref} className={`letter-glitch ${className}`} aria-hidden="true" />;
}
