import { useState, useEffect, useRef } from 'react';
import { playGlitchSound } from '../cyberAudio';

const GLYPHS = '01#$%=+*?~_<>[]{}&!|/\\ABCDEFXYZ0123456789';

export default function CyberGlitchText({ text = '', triggerOnHover = true, className = '', style = {}, playSound = false }) {
  const [displayText, setDisplayText] = useState(text);
  const isScrambling = useRef(false);

  const scramble = () => {
    if (isScrambling.current) return;
    isScrambling.current = true;
    if (playSound) playGlitchSound();

    let iteration = 0;
    const maxIterations = text.length;

    const interval = setInterval(() => {
      setDisplayText(
        text
          .split('')
          .map((char, index) => {
            if (char === ' ') return ' ';
            if (index < iteration) return text[index];
            return GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
          })
          .join('')
      );

      if (iteration >= maxIterations) {
        clearInterval(interval);
        setDisplayText(text);
        isScrambling.current = false;
      }

      iteration += 1 / 2;
    }, 25);
  };

  useEffect(() => {
    scramble();
  }, [text]);

  return (
    <span
      className={className}
      style={{
        display: 'inline-block',
        fontFamily: 'inherit',
        cursor: triggerOnHover ? 'crosshair' : 'inherit',
        ...style,
      }}
      onMouseEnter={() => {
        if (triggerOnHover) scramble();
      }}
    >
      {displayText}
    </span>
  );
}
