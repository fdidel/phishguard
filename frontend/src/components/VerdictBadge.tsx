/**
 * Verdict badge.
 *
 * Accessibility requirement: the status must be distinguishable **without**
 * relying on colour.  Every state therefore combines
 *   1. a distinct textual label,
 *   2. a distinct symbol (shape/character), and
 *   3. a distinct border style (solid / dashed / double / dotted / inset),
 * in addition to the colour.
 */

import type { Classification, ScanStatus } from '../types';

export type VerdictTone = 'safe' | 'suspicious' | 'dangerous' | 'inconclusive' | 'failed';

interface VerdictDescriptor {
  tone: VerdictTone;
  label: string;
  symbol: string;
  borderStyle: string;
  /** Short text used for screen readers and for the tooltip. */
  description: string;
}

/**
 * Resolve the visual descriptor for a scan.
 *
 * A failed or inconclusive scan NEVER resolves to the "safe" tone - this is
 * the single most important safety property of the dashboard.
 */
export function describeVerdict(
  classification: Classification,
  status: ScanStatus,
  label?: string,
): VerdictDescriptor {
  if (status === 'failed') {
    return {
      tone: 'failed',
      label: label || 'Analysis failed',
      symbol: '✖',
      borderStyle: 'inset',
      description:
        'The analysis could not be completed. This is not a safe result - no verdict was reached.',
    };
  }

  switch (classification) {
    case 'dangerous':
      return {
        tone: 'dangerous',
        label: label || 'Dangerous',
        symbol: '⛔',
        borderStyle: 'double',
        description:
          'Strong indicators of phishing. Do not enter credentials, payment details or personal data.',
      };
    case 'suspicious':
      return {
        tone: 'suspicious',
        label: label || 'Suspicious',
        symbol: '⚠',
        borderStyle: 'dashed',
        description:
          'Several suspicious characteristics were detected. Proceed with caution.',
      };
    case 'safe':
      return {
        tone: 'safe',
        label: label || 'No phishing indicators found',
        symbol: '✔',
        borderStyle: 'solid',
        description:
          'The URL did not match known phishing patterns. This is not a guarantee that the site is safe.',
      };
    case 'inconclusive':
    case 'unknown':
    default:
      return {
        tone: 'inconclusive',
        label: label || 'Inconclusive',
        symbol: '?',
        borderStyle: 'dotted',
        description:
          'There was not enough evidence to reach a verdict. Treat the site as unverified.',
      };
  }
}

interface VerdictBadgeProps {
  classification: Classification;
  status: ScanStatus;
  label?: string;
  /** Rendered next to the badge, e.g. the numeric risk score. */
  children?: React.ReactNode;
}

export default function VerdictBadge({
  classification,
  status,
  label,
  children,
}: VerdictBadgeProps) {
  const descriptor = describeVerdict(classification, status, label);

  return (
    <div
      className={`verdict verdict--${descriptor.tone}`}
      style={{ borderStyle: descriptor.borderStyle }}
      role="status"
      aria-live="polite"
    >
      <span className="verdict__symbol" aria-hidden="true">
        {descriptor.symbol}
      </span>
      <span className="verdict__body">
        <span className="verdict__label">{descriptor.label}</span>
        <span className="verdict__description">{descriptor.description}</span>
      </span>
      {children ? <span className="verdict__extra">{children}</span> : null}
    </div>
  );
}
