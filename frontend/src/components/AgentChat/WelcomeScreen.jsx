import React from 'react';

export default function WelcomeScreen() {
  return (
    <div className="flex flex-col items-center justify-center flex-1 p-6 text-center max-w-xl mx-auto my-auto animate-fade-up select-none">
      {/* Primary Heading */}
      <h1 className="font-display text-3xl sm:text-4xl font-extrabold text-[#3B1F73] tracking-tight mb-3 opacity-50">
        AppDB Agent
      </h1>

      {/* Supporting Description */}
      <p className="text-[14px] sm:text-[15px] text-slate-700 max-w-md leading-relaxed font-sans font-medium opacity-50">
        Your intelligent interface to AppDB. Ask questions, explore your data and get actionable insights instantly.
      </p>
    </div>
  );
}
