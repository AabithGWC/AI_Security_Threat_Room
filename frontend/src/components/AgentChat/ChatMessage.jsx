import React from 'react';
import DocCard, { extractDocCard } from './DocCard';
import { Hexagon, User } from 'lucide-react';

function formatText(text) {
  if (!text) return '';
  const escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  const formattedCode = escaped.replace(
    /`([^`]+)`/g,
    '<code class="bg-[#462C7D]/10 text-[#462C7D] px-1.5 py-0.5 rounded text-xs font-mono font-semibold">$1</code>'
  );

  const formattedBold = formattedCode.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  return formattedBold.replace(/\n/g, '<br/>');
}

export function TypingIndicator() {
  return (
    <div className="flex gap-2.5 items-start animate-fade-up">
      <div className="w-7 h-7 rounded-xl bg-[#462C7D]/10 border border-[#462C7D]/20 text-[#462C7D] flex items-center justify-center font-bold text-xs shrink-0">
        <Hexagon className="w-4 h-4 text-[#831C91]" />
      </div>
      <div className="px-3.5 py-2.5 bg-white border border-[#462C7D]/15 rounded-2xl rounded-tl-sm shadow-xs flex items-center">
        <span className="text-xs font-mono font-medium text-[#831C91]">Thinking...</span>
      </div>
    </div>
  );
}

export default function ChatMessage({ message }) {
  const { role, text, time, meta } = message;
  const isUser = role === 'user';
  const docCard = !isUser ? extractDocCard(text) : null;

  return (
    <div className={`flex gap-2.5 animate-fade-up ${isUser ? 'flex-row-reverse' : ''}`}>
      <div
        className={`w-7 h-7 rounded-xl flex items-center justify-center shrink-0 font-semibold text-xs mt-0.5 ${
          isUser
            ? 'bg-gradient-to-br from-[#462C7D] to-[#831C91] text-white shadow-md shadow-[#462C7D]/20'
            : 'bg-[#462C7D]/10 border border-[#462C7D]/20 text-[#462C7D]'
        }`}
      >
        {isUser ? <User className="w-4 h-4 text-white" /> : <Hexagon className="w-4 h-4 text-[#831C91]" />}
      </div>

      <div className={`max-w-[75%] flex flex-col gap-1 ${isUser ? 'items-end' : ''}`}>
        <div
          className={`px-4 py-3 rounded-2xl text-[13.5px] leading-relaxed shadow-xs ${
            isUser
              ? 'bg-gradient-to-br from-[#462C7D] to-[#831C91] text-white rounded-tr-sm shadow-md shadow-[#462C7D]/15'
              : 'bg-white border border-[#462C7D]/15 text-[#1E1235] rounded-tl-sm'
          } ${meta?.error ? 'border-[#9C2652] bg-[#FAF8FC] text-[#9C2652]' : ''}`}
        >
          {docCard ? (
            <>
              <div
                dangerouslySetInnerHTML={{ __html: formatText(docCard.preText) }}
              />
              <DocCard docCardData={docCard} />
              {docCard.postText && (
                <div
                  className="mt-2"
                  dangerouslySetInnerHTML={{ __html: formatText(docCard.postText) }}
                />
              )}
            </>
          ) : (
            <div dangerouslySetInnerHTML={{ __html: formatText(text) }} />
          )}
        </div>

        <span className="text-[10px] text-slate-400 px-1 font-mono">{time}</span>
      </div>
    </div>
  );
}
