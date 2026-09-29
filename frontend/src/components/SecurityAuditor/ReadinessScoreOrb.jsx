import React from 'react';

export default function ReadinessScoreOrb({ score, visible, statusText, isLoading = false }) {
  if (!visible) return null;

  const isInitial = score === null || score === undefined;
  const displayScore = score !== null && score !== undefined ? score : '--';
  const numericScore = typeof score === 'number' ? score : 0;

  const circumference = 440;
  const offset = isInitial ? circumference : circumference - (numericScore / 100) * circumference;

  // Dynamic Readiness Score States & Transitions:
  // < 50%  -> Orange
  // 50-69% -> Orange-Yellow
  // 70-89% -> Bright Yellow
  // 90-99% -> Strong Golden Yellow
  // 100%   -> Emerald Green
  const isFullSuccess = !isInitial && numericScore === 100;
  const isWarning = !isInitial && numericScore < 50;
  const isOrangeYellow = !isInitial && numericScore >= 50 && numericScore < 70;
  const isBrightYellow = !isInitial && numericScore >= 70 && numericScore < 90;
  const isGoldenYellow = !isInitial && numericScore >= 90 && numericScore < 100;

  let gradientId = 'purpleGrad';
  let ringFilter = 'none';
  let textColorClass = 'text-[#3C1F73] font-extrabold';
  let glowContainerClass = '';

  if (isFullSuccess) {
    gradientId = 'greenGrad';
    ringFilter = 'drop-shadow-[0_0_14px_rgba(16,185,129,0.45)]';
    textColorClass = 'text-emerald-600 font-extrabold';
    glowContainerClass = 'animate-pulse';
  } else if (isWarning) {
    gradientId = 'orangeGrad';
    ringFilter = 'drop-shadow-[0_0_12px_rgba(249,115,22,0.4)]';
    textColorClass = 'text-orange-600 font-extrabold';
  } else if (isOrangeYellow) {
    gradientId = 'orangeYellowGrad';
    ringFilter = 'drop-shadow-[0_0_12px_rgba(245,158,11,0.4)]';
    textColorClass = 'text-amber-600 font-extrabold';
  } else if (isBrightYellow) {
    gradientId = 'brightYellowGrad';
    ringFilter = 'drop-shadow-[0_0_13px_rgba(234,179,8,0.45)]';
    textColorClass = 'text-yellow-600 font-extrabold';
  } else if (isGoldenYellow) {
    gradientId = 'goldenYellowGrad';
    ringFilter = 'drop-shadow-[0_0_14px_rgba(217,119,6,0.45)]';
    textColorClass = 'text-amber-700 font-extrabold';
  }

  return (
    <div className="bg-white border border-[#462C7D]/20 rounded-2xl p-4.5 sm:p-5.5 px-5 sm:px-7 min-h-[120px] shadow-xs flex flex-col sm:flex-row items-center text-center sm:text-left gap-4 sm:gap-6 transition-all relative overflow-hidden w-full">
      {/* Subtly Animated Water & Translucent Bubble Loading Effect Overlay */}
      <style>{`
        @keyframes waterWave {
          0%, 100% { transform: translateY(0) scaleY(1); }
          50% { transform: translateY(-4px) scaleY(1.04); }
        }
        @keyframes bubbleFloat1 {
          0% { transform: translate(0, 10px) scale(0.6); opacity: 0; }
          50% { opacity: 0.55; }
          100% { transform: translate(-14px, -30px) scale(1.1); opacity: 0; }
        }
        @keyframes bubbleFloat2 {
          0% { transform: translate(0, 10px) scale(0.5); opacity: 0; }
          50% { opacity: 0.6; }
          100% { transform: translate(16px, -35px) scale(1.25); opacity: 0; }
        }
        @keyframes bubbleFloat3 {
          0% { transform: translate(0, 10px) scale(0.7); opacity: 0; }
          50% { opacity: 0.45; }
          100% { transform: translate(6px, -40px) scale(1); opacity: 0; }
        }
        .animate-water-wave {
          animation: waterWave 3s ease-in-out infinite;
        }
        .animate-bubble-1 {
          animation: bubbleFloat1 2.8s ease-in-out infinite;
        }
        .animate-bubble-2 {
          animation: bubbleFloat2 3.4s ease-in-out infinite 0.6s;
        }
        .animate-bubble-3 {
          animation: bubbleFloat3 3.1s ease-in-out infinite 1.2s;
        }
      `}</style>

      {/* Water & Bubble Loading Overlay Container */}
      <div
        className={`absolute inset-0 pointer-events-none rounded-2xl overflow-hidden transition-opacity duration-500 z-0 ${
          isLoading ? 'opacity-100' : 'opacity-0'
        }`}
      >
        {/* Soft flowing water wave background matching score color */}
        <div
          className={`absolute inset-0 transition-colors duration-500 animate-water-wave opacity-35 ${
            isFullSuccess
              ? 'bg-gradient-to-r from-emerald-100/50 via-teal-50/60 to-emerald-100/50'
              : isWarning
              ? 'bg-gradient-to-r from-orange-100/50 via-amber-50/60 to-orange-100/50'
              : isOrangeYellow
              ? 'bg-gradient-to-r from-amber-100/50 via-yellow-50/60 to-amber-100/50'
              : isBrightYellow
              ? 'bg-gradient-to-r from-yellow-100/50 via-amber-50/60 to-yellow-100/50'
              : 'bg-gradient-to-r from-amber-200/40 via-yellow-100/50 to-amber-200/40'
          }`}
        />

        {/* Floating translucent bubbles matching readiness state color */}
        {isLoading && (
          <>
            <div
              className={`absolute bottom-2 left-[18%] w-5 h-5 rounded-full blur-[1px] animate-bubble-1 ${
                isFullSuccess
                  ? 'bg-emerald-400/30 border border-emerald-300/40'
                  : isWarning
                  ? 'bg-orange-400/30 border border-orange-300/40'
                  : 'bg-amber-400/30 border border-yellow-300/40'
              }`}
            />
            <div
              className={`absolute bottom-1 left-[48%] w-6 h-6 rounded-full blur-[1px] animate-bubble-2 ${
                isFullSuccess
                  ? 'bg-teal-400/30 border border-teal-300/40'
                  : isWarning
                  ? 'bg-amber-400/30 border border-amber-300/40'
                  : 'bg-yellow-400/30 border border-amber-300/40'
              }`}
            />
            <div
              className={`absolute bottom-3 left-[78%] w-4 h-4 rounded-full blur-[1px] animate-bubble-3 ${
                isFullSuccess
                  ? 'bg-emerald-300/35 border border-emerald-200/40'
                  : isWarning
                  ? 'bg-orange-300/35 border border-orange-200/40'
                  : 'bg-amber-300/35 border border-yellow-200/40'
              }`}
            />
          </>
        )}
      </div>

      <div className={`relative w-20 h-20 sm:w-24 sm:h-24 shrink-0 z-10 ${glowContainerClass}`}>
        <svg className={`w-full h-full -rotate-90 filter transition-all duration-700 ${ringFilter}`} viewBox="0 0 160 160">
          <defs>
            {/* Green Gradient for 100% Score */}
            <linearGradient id="greenGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#059669" />
              <stop offset="50%" stopColor="#10B981" />
              <stop offset="100%" stopColor="#34D399" />
            </linearGradient>

            {/* Orange Gradient for <50% Score */}
            <linearGradient id="orangeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#D97706" />
              <stop offset="50%" stopColor="#F97316" />
              <stop offset="100%" stopColor="#FBBF24" />
            </linearGradient>

            {/* Orange-Yellow Gradient for 50-69% Score */}
            <linearGradient id="orangeYellowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#F97316" />
              <stop offset="50%" stopColor="#F59E0B" />
              <stop offset="100%" stopColor="#EAB308" />
            </linearGradient>

            {/* Bright Yellow Gradient for 70-89% Score */}
            <linearGradient id="brightYellowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#F59E0B" />
              <stop offset="50%" stopColor="#EAB308" />
              <stop offset="100%" stopColor="#CA8A04" />
            </linearGradient>

            {/* Strong Golden Yellow Gradient for 90-99% Score */}
            <linearGradient id="goldenYellowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#EAB308" />
              <stop offset="50%" stopColor="#D97706" />
              <stop offset="100%" stopColor="#B45309" />
            </linearGradient>
          </defs>
          <circle
            cx="80"
            cy="80"
            r="70"
            className="fill-none stroke-[#462C7D]/12 stroke-[11]"
          />
          <circle
            cx="80"
            cy="80"
            r="70"
            className="fill-none stroke-[11] stroke-linecap-round transition-all duration-1000 ease-out"
            style={{
              stroke: isInitial ? 'transparent' : `url(#${gradientId})`,
              strokeDasharray: circumference,
              strokeDashoffset: offset,
            }}
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-display text-lg sm:text-xl transition-colors duration-700 ${textColorClass}`}>
            {displayScore}%
          </span>
          <span className="text-[7.5px] sm:text-[8px] text-slate-500 font-mono tracking-widest uppercase font-bold mt-0.5">
            Readiness
          </span>
        </div>
      </div>

      <div className="flex-1 text-center sm:text-left z-10">
        <h3 className="text-sm sm:text-base font-extrabold text-[#3B1F73] font-display mb-0.5 sm:mb-1">
          Production Security Readiness
        </h3>
        <p className="text-[11px] sm:text-xs text-slate-600 leading-relaxed font-mono break-words font-medium">
          {statusText ||
            'Dynamically calculated from threat severity, system permissions and mitigation status.'}
        </p>
      </div>
    </div>
  );
}
