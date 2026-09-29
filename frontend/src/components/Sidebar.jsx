import React from 'react';
import { MessageSquare, Shield, Plus, X } from 'lucide-react';

function SidebarInnerContent({ activeTab, onSelectTab, onNewChat, activeSessionText, onCloseMobile, isMobile }) {
  return (
    <>
      {/* Mobile Close Button */}
      {isMobile && (
        <button
          onClick={onCloseMobile}
          className="md:hidden absolute top-3.5 right-3.5 p-1.5 text-slate-400 hover:text-[#462C7D] hover:bg-[#462C7D]/10 rounded-xl transition-colors cursor-pointer z-10"
          title="Close navigation"
        >
          <X className="w-5 h-5" />
        </button>
      )}

      {/* Centered Elevated Brand Topbar Card */}
      <div className="bg-white rounded-[22px] border border-[#462C7D]/22 p-4 pt-5 pb-4.5 mb-3 flex flex-col items-center text-center shadow-xs relative">
        {/* Centered Wide Logo */}
        <div className="relative mb-3 group w-full flex justify-center">
          <img
            src="/gwc-data-ai-logo.png"
            alt="GWC DATA.AI Logo"
            className="h-9 w-auto object-contain max-w-[190px] group-hover:scale-[1.03] transition-transform duration-200"
            onError={(e) => { e.currentTarget.src = '/gwc-logo.jpg'; }}
          />
        </div>

        {/* Centered Title & Subtitle */}
        <div className="font-display text-sm font-extrabold text-[#3B1F73] leading-snug">
          AppDB Agent
        </div>
        <div className="text-[10.5px] text-[#4C2882] font-mono font-medium mt-0.5 mb-3.5">
          Powered by GWC Data
        </div>

        {/* Premium Interactive New Conversation Button */}
        <button
          onClick={onNewChat}
          className="w-full flex items-center justify-center gap-2 py-2.5 px-3 bg-[#FAF6FE] hover:bg-[#8E1E9E]/10 hover:border-[#8E1E9E]/40 border border-[#4C2882]/25 rounded-xl text-[#3C1F73] hover:text-[#8E1E9E] text-xs font-extrabold transition-all duration-200 shadow-2xs hover:shadow-md hover:-translate-y-0.5 cursor-pointer group"
        >
          <Plus className="w-4 h-4 text-[#8E1E9E] group-hover:scale-110 transition-transform stroke-[2.2]" />
          <span>New conversation</span>
        </button>
      </div>

      {/* Navigation Links Card Container */}
      <div className="bg-white/95 backdrop-blur-sm rounded-[22px] border border-[#462C7D]/20 p-3 mb-3 shadow-xs">
        <div className="text-[10px] font-extrabold tracking-wider uppercase text-[#8E1E9E] font-mono mb-2 px-2">
          Navigation
        </div>

        <div className="flex flex-col gap-1.5">
          <button
            onClick={() => onSelectTab('auditor')}
            className={`flex items-center gap-2.5 px-3.5 py-2.5 rounded-[16px] text-xs transition-all duration-200 ease-out relative cursor-pointer group ${
              activeTab === 'auditor'
                ? 'bg-gradient-to-r from-[#4C2882] via-[#8E1E9E] to-[#D84BA1] text-white font-extrabold shadow-md shadow-[#4C2882]/20 border border-white/20 scale-[1.01]'
                : 'text-[#3C1F73] font-bold hover:bg-[#4C2882]/8 hover:text-[#3C1F73]'
            }`}
          >
            <Shield className={`w-4 h-4 shrink-0 transition-transform duration-200 group-hover:scale-105 stroke-[2.2] ${activeTab === 'auditor' ? 'text-white' : 'text-[#8E1E9E]'}`} />
            <span>Security Auditor</span>
          </button>

          <button
            onClick={() => onSelectTab('chat')}
            className={`flex items-center gap-2.5 px-3.5 py-2.5 rounded-[16px] text-xs transition-all duration-220 ease-out cursor-pointer ${
              activeTab === 'chat'
                ? 'bg-gradient-to-r from-[#4C2882] via-[#8E1E9E] to-[#D84BA1] text-white font-extrabold shadow-md shadow-[#4C2882]/20 border border-white/20 scale-[1.01]'
                : 'text-[#3C1F73] font-bold hover:bg-[#4C2882]/8 hover:text-[#3C1F73]'
            }`}
          >
            <MessageSquare className="w-4 h-4 shrink-0 transition-transform duration-220 stroke-[2.2]" />
            <span>Agent Chat</span>
          </button>
        </div>
      </div>

      {/* Sessions Section Container */}
      <div className="bg-white/95 backdrop-blur-sm rounded-[22px] border border-[#462C7D]/20 p-3 flex-1 overflow-y-auto shadow-xs">
        <div className="text-[10px] font-extrabold tracking-wider uppercase text-slate-500 font-mono mb-2 px-2">
          Recent Sessions
        </div>

        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl bg-[#4C2882]/8 text-[#3C1F73] font-bold text-xs border border-[#4C2882]/20 shadow-2xs hover:border-[#8E1E9E]/40 transition-colors cursor-pointer truncate">
            <MessageSquare className="w-3.5 h-3.5 shrink-0 text-[#8E1E9E]" />
            <span className="truncate">{activeSessionText || 'Current session'}</span>
          </div>
        </div>
      </div>
    </>
  );
}

export default function Sidebar({ activeTab, onSelectTab, onNewChat, activeSessionText, isOpenMobile, onCloseMobile, hideDesktop = false }) {
  return (
    <>
      {/* 1. DESKTOP SIDEBAR (Static, Un-animated) */}
      <aside className={`${hideDesktop ? 'hidden' : 'hidden md:flex'} w-60 lg:w-68 bg-[#F6F3FC] border-r border-[#462C7D]/20 flex-col shrink-0 overflow-hidden h-full shadow-[4px_0_24px_rgba(70,44,125,0.06)] z-20 p-3`}>
        <SidebarInnerContent
          activeTab={activeTab}
          onSelectTab={onSelectTab}
          onNewChat={onNewChat}
          activeSessionText={activeSessionText}
          isMobile={false}
        />
      </aside>

      {/* 2. MOBILE BACKDROP OVERLAY (Fade transition 300ms) */}
      <div
        onClick={onCloseMobile}
        className={`md:hidden fixed inset-0 bg-[#1E1235]/40 backdrop-blur-xs z-40 transition-opacity duration-300 ease-in-out ${
          isOpenMobile ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'
        }`}
      />

      {/* 3. MOBILE SIDEBAR DRAWER (Slide transition 300ms cubic-bezier) */}
      <aside
        className={`md:hidden fixed inset-y-0 left-0 z-50 w-72 max-w-[82vw] bg-[#F6F3FC] border-r border-[#462C7D]/20 flex flex-col p-3 shadow-[8px_0_30px_rgba(30,18,53,0.2)] transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)] ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <SidebarInnerContent
          activeTab={activeTab}
          onSelectTab={(tab) => {
            if (onCloseMobile) onCloseMobile();
            onSelectTab(tab);
          }}
          onNewChat={() => {
            if (onCloseMobile) onCloseMobile();
            onNewChat();
          }}
          activeSessionText={activeSessionText}
          onCloseMobile={onCloseMobile}
          isMobile={true}
        />
      </aside>
    </>
  );
}
