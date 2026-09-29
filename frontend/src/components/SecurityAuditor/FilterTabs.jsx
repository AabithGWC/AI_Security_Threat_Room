import React from 'react';

export default function FilterTabs({ activeFilter, onSelectFilter, counts }) {
  const tabs = [
    { key: 'all', label: 'All', count: counts.all || 0 },
    { key: 'critical', label: 'Critical', count: counts.critical || 0 },
    { key: 'high', label: 'High', count: counts.high || 0 },
    { key: 'medium', label: 'Medium', count: counts.medium || 0 },
    { key: 'resolved', label: 'Resolved', count: counts.resolved || 0 },
  ];

  return (
    <div className="flex gap-2 flex-wrap items-center">
      {tabs.map((tab) => {
        const isActive = activeFilter === tab.key;
        return (
          <button
            key={tab.key}
            onClick={() => onSelectFilter(tab.key)}
            className={`px-3 py-1.5 rounded-xl text-[11.5px] font-extrabold font-mono border transition-all flex items-center gap-1.5 cursor-pointer shadow-2xs ${
              isActive
                ? 'bg-gradient-to-r from-[#4C2882] via-[#8E1E9E] to-[#D84BA1] text-white border-transparent shadow-md shadow-[#4C2882]/20 scale-[1.02]'
                : 'bg-white text-[#3C1F73] border-[#4C2882]/28 hover:border-[#8E1E9E]/50 hover:bg-[#4C2882]/8'
            }`}
          >
            <span>{tab.label}</span>
            <span
              className={`px-1.5 py-0.2 rounded-md text-[10px] font-extrabold ${
                isActive
                  ? 'bg-white/25 text-white'
                  : 'bg-[#4C2882]/12 text-[#3C1F73]'
              }`}
            >
              {tab.count}
            </span>
          </button>
        );
      })}
    </div>
  );
}
