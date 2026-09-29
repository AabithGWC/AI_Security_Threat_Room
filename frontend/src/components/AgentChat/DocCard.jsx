import React from 'react';

export function extractDocCard(text) {
  if (!text) return null;
  const match = text.match(/\{[\s\S]*"document_id"[\s\S]*\}/);
  if (!match) return null;
  try {
    const data = JSON.parse(match[0]);
    return {
      preText: text.slice(0, text.indexOf(match[0])).trim(),
      postText: text.slice(text.indexOf(match[0]) + match[0].length).trim(),
      data,
    };
  } catch {
    return null;
  }
}

export default function DocCard({ docCardData }) {
  if (!docCardData || !docCardData.data) return null;

  const { data } = docCardData;
  const docId = data.document_id || data.id || '—';
  const displayId = docId.length > 20 ? `${docId.slice(0, 10)}…${docId.slice(-6)}` : docId;
  const isDeleted = Boolean(data.deleted);
  const contentObj = data.content || data;

  return (
    <div className="mt-3 rounded-xl border border-[#462C7D]/15 bg-[#FAF8FC] overflow-hidden">
      <div className="flex items-center justify-between px-3.5 py-2 bg-white border-b border-[#462C7D]/10">
        <span className="font-mono text-xs text-[#462C7D] font-semibold">{displayId}</span>
        <span
          className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
            isDeleted
              ? 'bg-slate-100 text-slate-500 border-slate-200'
              : 'bg-[#831C91]/10 text-[#831C91] border-[#831C91]/25'
          }`}
        >
          {isDeleted ? 'deleted' : 'match'}
        </span>
      </div>

      <div className="p-3.5 flex flex-col gap-1.5 text-xs">
        {Object.entries(contentObj).map(([key, val]) => {
          if (key === 'document_id' || key === 'id') return null;
          return (
            <div key={key} className="flex gap-3">
              <span className="font-mono text-slate-500 min-w-[80px]">{key}</span>
              <span className="text-[#1E1235] font-medium">{String(val)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
