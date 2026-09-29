import React from 'react';
import ThreatDetailsModal from './ThreatDetailsModal';
import { getNodeDetails } from '../../data/securityNodeDetails';

export default function StageDetailModal({ stageId, node, isOpen, onClose, onResolve }) {
  if (!isOpen) return null;

  const nodeKey = node || stageId;
  if (!nodeKey) return null;

  const threatObj = getNodeDetails(nodeKey);

  return (
    <ThreatDetailsModal
      threat={threatObj}
      isOpen={isOpen}
      onClose={onClose}
      onResolve={onResolve}
    />
  );
}
