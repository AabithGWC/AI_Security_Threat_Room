import React, { useState, useRef } from 'react';
import Sidebar from './components/Sidebar';
import ChatArea from './components/AgentChat/ChatArea';
import AuditorDashboard from './components/SecurityAuditor/AuditorDashboard';
import ConfirmModal from './components/common/ConfirmModal';

export default function App() {
  const [activeTab, setActiveTab] = useState('auditor'); // Sidebar active highlight state
  const [displayedTab, setDisplayedTab] = useState('auditor'); // Main view currently rendered
  const [animState, setAnimState] = useState('entering'); // 'exiting' | 'entering'
  const [showNewChatModal, setShowNewChatModal] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const timerRef = useRef(null);

  const handleSelectTab = (targetTab) => {
    setMobileSidebarOpen(false);
    if (targetTab === activeTab && targetTab === displayedTab) return;

    // 1. Immediately highlight target tab in sidebar (220ms smooth CSS button transition)
    setActiveTab(targetTab);

    // 2. Clear any pending transition timers
    if (timerRef.current) clearTimeout(timerRef.current);

    // 3. Trigger smooth exit transition on current main page (120ms exit)
    setAnimState('exiting');

    // 4. After exit animation, swap view and trigger enter transition (320ms enter)
    timerRef.current = setTimeout(() => {
      setDisplayedTab(targetTab);
      setAnimState('entering');
    }, 120);
  };

  const handleConfirmNewChat = () => {
    setMobileSidebarOpen(false);
    setShowNewChatModal(false);
    localStorage.removeItem('agent_session');
    setActiveTab('chat');
    window.location.reload();
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden relative z-1 bg-gradient-to-br from-[#F8F5FD] via-[#F4EFFB] to-[#F0EAF8]">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={handleSelectTab}
        onNewChat={() => {
          setMobileSidebarOpen(false);
          setShowNewChatModal(true);
        }}
        isOpenMobile={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
        hideDesktop={displayedTab !== 'chat'}
      />

      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        <div
          className={`flex-1 flex flex-col h-full overflow-hidden ${
            animState === 'exiting' ? 'animate-page-exit' : 'animate-page-enter'
          }`}
        >
          {displayedTab === 'chat' ? (
            <ChatArea
              onOpenSecurityAuditor={() => handleSelectTab('auditor')}
              onOpenMobileMenu={() => setMobileSidebarOpen(true)}
            />
          ) : (
            <AuditorDashboard onBackToChat={() => handleSelectTab('chat')} />
          )}
        </div>
      </main>

      {/* Custom Reusable Confirmation Modal */}
      <ConfirmModal
        open={showNewChatModal}
        title="Start New Conversation"
        message="Are you sure you want to start a new conversation?"
        description="Your current conversation will be cleared."
        confirmText="Start New Chat"
        cancelText="Cancel"
        onConfirm={handleConfirmNewChat}
        onCancel={() => setShowNewChatModal(false)}
      />
    </div>
  );
}
