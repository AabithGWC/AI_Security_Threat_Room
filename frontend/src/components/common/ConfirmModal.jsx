import React, { useEffect } from 'react';
import { MessageSquarePlus, X } from 'lucide-react';

export default function ConfirmModal({
  open,
  title = 'Start New Conversation',
  message = 'Are you sure you want to start a new conversation?',
  description = 'Your current conversation will be cleared.',
  confirmText = 'Start New Chat',
  cancelText = 'Cancel',
  onConfirm,
  onCancel,
}) {
  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && open && onCancel) {
        onCancel();
      }
    };
    if (open) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onCancel]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 bg-[#1E1235]/60 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fade-in"
      onClick={onCancel}
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-modal-title"
    >
      {/* Modal Surface */}
      <div
        className="bg-white border border-[#462C7D]/20 rounded-3xl p-6 sm:p-7 max-w-md w-full shadow-[0_25px_70px_-15px_rgba(70,44,125,0.35)] relative animate-fade-up overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button Top-Right */}
        <button
          onClick={onCancel}
          className="absolute top-4 right-4 p-2 text-slate-400 hover:text-[#462C7D] rounded-full hover:bg-[#462C7D]/10 transition-colors cursor-pointer"
          title="Close Modal"
          aria-label="Close modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-4 pr-6">
          <div className="w-10 h-10 rounded-2xl bg-gradient-to-br from-[#462C7D] via-[#831C91] to-[#D552A3] text-white flex items-center justify-center shadow-md shadow-[#462C7D]/25 shrink-0">
            <MessageSquarePlus className="w-5.5 h-5.5 stroke-[2.2]" />
          </div>
          <h3 id="confirm-modal-title" className="font-display font-bold text-[#462C7D] text-lg sm:text-xl">
            {title}
          </h3>
        </div>

        {/* Modal Body */}
        <div className="mb-6 bg-[#FAF8FC] border border-[#462C7D]/10 p-4 rounded-2xl">
          <p className="font-bold text-[#1E1235] text-sm leading-snug mb-1">
            {message}
          </p>
          <p className="text-slate-500 text-xs font-mono leading-relaxed">
            {description}
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          <button
            onClick={onCancel}
            className="flex-1 py-2.5 px-4 rounded-xl text-xs font-bold text-[#462C7D] bg-white border border-[#462C7D]/25 hover:bg-[#462C7D]/10 transition-all cursor-pointer shadow-2xs"
          >
            {cancelText}
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 py-2.5 px-4 rounded-xl text-xs font-bold text-white bg-gradient-to-r from-[#462C7D] to-[#831C91] hover:brightness-110 shadow-md shadow-[#462C7D]/20 transition-all cursor-pointer"
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
