import React, { useState, useRef, useEffect } from 'react';
import ChatMessage, { TypingIndicator } from './ChatMessage';
import WelcomeScreen from './WelcomeScreen';
import ConfirmModal from '../common/ConfirmModal';
import { Shield, RotateCcw, Download, Send, Menu } from 'lucide-react';
import { sendChatMessage } from '../../api/backend';

export default function ChatArea({ onOpenSecurityAuditor, onOpenMobileMenu }) {
  const [messages, setMessages] = useState([]);
  const [sessionId, setSessionId] = useState(null);
  const [inputVal, setInputVal] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showClearModal, setShowClearModal] = useState(false);
  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  // Load history from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('agent_session');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        setSessionId(parsed.id || null);
        setMessages(parsed.history || []);
      } catch (err) {
        console.error('Failed to parse saved chat session:', err);
      }
    }
  }, []);

  // Save history to localStorage
  const saveSession = (newSessionId, newHistory) => {
    localStorage.setItem(
      'agent_session',
      JSON.stringify({ id: newSessionId, history: newHistory })
    );
  };

  // Scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  // Auto-resize textarea
  const handleInput = (e) => {
    setInputVal(e.target.value);
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 120)}px`;
    }
  };

  const getTimeStr = () =>
    new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const handleSend = async () => {
    const trimmed = inputVal.trim();
    if (!trimmed || isLoading) return;

    const time = getTimeStr();
    const userMsg = { role: 'user', text: trimmed, time };
    const updatedMessages = [...messages, userMsg];

    setMessages(updatedMessages);
    setInputVal('');
    if (textareaRef.current) textareaRef.current.style.height = 'auto';
    setIsLoading(true);

    try {
      const res = await sendChatMessage(trimmed, sessionId);
      const activeSessionId = res.session_id;
      setSessionId(activeSessionId);

      const agentMsg = { role: 'agent', text: res.reply, time: getTimeStr() };
      const finalHistory = [...updatedMessages, agentMsg];
      setMessages(finalHistory);
      saveSession(activeSessionId, finalHistory);
    } catch (err) {
      const errMsg = {
        role: 'agent',
        text: `⚠️ ${err.message}`,
        time: getTimeStr(),
        meta: { error: true },
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleClearChatRequest = () => {
    setShowClearModal(true);
  };

  const handleConfirmClearChat = () => {
    setShowClearModal(false);
    setMessages([]);
    setSessionId(null);
    localStorage.removeItem('agent_session');
  };

  const handleExportChat = () => {
    if (!messages.length) return;
    const lines = messages
      .map((m) => `[${m.time}] ${m.role.toUpperCase()}: ${m.text}`)
      .join('\n\n');
    const blob = new Blob([lines], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `agent-chat-${Date.now()}.txt`;
    a.click();
  };

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-transparent relative z-1">
      {/* Floating White Header Surface (Level 2 Depth) */}
      <div className="flex items-center justify-between mx-2.5 sm:mx-4 mt-3.5 px-3.5 sm:px-6 py-3.5 bg-white border border-[#462C7D]/20 rounded-[22px] shrink-0 shadow-xs z-20">
        <div className="flex items-center gap-2.5">
          {/* Mobile Menu Toggle */}
          <button
            onClick={onOpenMobileMenu}
            className="md:hidden w-8.5 h-8.5 flex items-center justify-center bg-white hover:bg-[#FAF6FE] border border-[#462C7D]/20 rounded-xl text-[#3C1F73] hover:text-[#8E1E9E] cursor-pointer shrink-0"
            title="Open Menu"
          >
            <Menu className="w-4.5 h-4.5 stroke-[2.2]" />
          </button>
          <div>
            <div className="font-display font-extrabold text-[#3B1F73] text-sm sm:text-base tracking-tight">
              AppDB Agent
            </div>
            <div className="text-[11px] sm:text-xs text-[#4C2882] font-mono font-medium">
              {sessionId ? 'Session active' : 'Ready to assist'} · {messages.length} messages
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Action Icon Buttons */}
          <button
            onClick={handleClearChatRequest}
            className="w-8.5 h-8.5 flex items-center justify-center bg-white hover:bg-[#FAF6FE] border border-[#462C7D]/22 hover:border-[#8E1E9E]/40 rounded-xl text-[#3C1F73] hover:text-[#8E1E9E] transition-all duration-200 shadow-2xs hover:shadow-md hover:-translate-y-0.5 cursor-pointer"
            title="Clear chat"
          >
            <RotateCcw className="w-4 h-4 stroke-[2.2]" />
          </button>

          <button
            onClick={handleExportChat}
            className="w-8.5 h-8.5 flex items-center justify-center bg-white hover:bg-[#FAF6FE] border border-[#462C7D]/22 hover:border-[#8E1E9E]/40 rounded-xl text-[#3C1F73] hover:text-[#8E1E9E] transition-all duration-200 shadow-2xs hover:shadow-md hover:-translate-y-0.5 cursor-pointer"
            title="Export chat"
          >
            <Download className="w-4 h-4 stroke-[2.2]" />
          </button>
        </div>
      </div>

      {/* Message Stream Workspace (Level 1 Depth) */}
      <div className="flex-1 overflow-y-auto no-scrollbar p-7 flex flex-col gap-5 max-w-4xl mx-auto w-full">
        {messages.length === 0 ? (
          <WelcomeScreen />
        ) : (
          messages.map((msg, idx) => <ChatMessage key={idx} message={msg} />)
        )}
        {isLoading && <TypingIndicator />}
        <div ref={messagesEndRef} />
      </div>

      {/* Floating Chat Composer (Level 3 Depth) */}
      <div className="p-4 px-6 pb-6 bg-gradient-to-t from-[#F8F5FD] via-[#F8F5FD]/80 to-transparent shrink-0">
        <div className="max-w-4xl mx-auto w-full">
          <div className="flex gap-3 items-end p-2 bg-white rounded-[22px] border border-[#4C2882]/25 shadow-sm focus-within:border-[#8E1E9E] focus-within:ring-4 focus-within:ring-[#8E1E9E]/15 transition-all duration-200">
            <div className="flex-1 px-3.5 py-1">
              <textarea
                ref={textareaRef}
                value={inputVal}
                onChange={handleInput}
                onKeyDown={handleKeyDown}
                placeholder="Ask about your data…"
                rows={1}
                className="w-full bg-transparent border-none outline-none text-[#1E1235] text-[14px] py-1.5 resize-none max-h-[120px] leading-relaxed font-sans placeholder:text-slate-500 font-medium"
              />
            </div>

            {/* Floating Action Send Button */}
            <button
              onClick={handleSend}
              disabled={isLoading || !inputVal.trim()}
              className="w-11 h-11 bg-gradient-to-r from-[#4C2882] via-[#8E1E9E] to-[#D84BA1] hover:brightness-110 active:scale-95 disabled:opacity-40 disabled:hover:brightness-100 border-none rounded-2xl flex items-center justify-center cursor-pointer transition-all duration-200 text-white shadow-md shadow-[#4C2882]/25 hover:-translate-y-0.5 hover:shadow-lg shrink-0"
              title="Send"
            >
              <Send className="w-4.5 h-4.5 text-white stroke-[2.2]" />
            </button>
          </div>

          <div className="text-[11px] text-[#4C2882]/80 text-center mt-2.5 font-mono font-medium">
            Press Enter to send &middot; Shift+Enter for new line
          </div>
        </div>
      </div>

      {/* Custom Reusable Confirmation Modal for Clear Chat */}
      <ConfirmModal
        open={showClearModal}
        title="Start New Conversation"
        message="Are you sure you want to start a new conversation?"
        description="Your current conversation will be cleared."
        confirmText="Start New Chat"
        cancelText="Cancel"
        onConfirm={handleConfirmClearChat}
        onCancel={() => setShowClearModal(false)}
      />
    </div>
  );
}
