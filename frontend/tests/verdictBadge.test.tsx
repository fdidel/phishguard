/**
 * The verdict descriptor is the single place where a classification becomes a
 * user-visible status, so its safety properties are tested directly.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import VerdictBadge, { describeVerdict } from '../src/components/VerdictBadge';

describe('describeVerdict', () => {
  it('maps each classification to a distinct tone', () => {
    expect(describeVerdict('safe', 'completed').tone).toBe('safe');
    expect(describeVerdict('suspicious', 'completed').tone).toBe('suspicious');
    expect(describeVerdict('dangerous', 'completed').tone).toBe('dangerous');
    expect(describeVerdict('inconclusive', 'inconclusive').tone).toBe('inconclusive');
    expect(describeVerdict('unknown', 'completed').tone).toBe('inconclusive');
  });

  it('never resolves a failed scan to the safe tone', () => {
    // Even if a mis-wired backend returns classification="safe" with a failed
    // status, the badge must not show it as safe.
    const descriptor = describeVerdict('safe', 'failed');
    expect(descriptor.tone).toBe('failed');
    expect(descriptor.tone).not.toBe('safe');
    expect(descriptor.label.toLowerCase()).toContain('fail');
  });

  it('gives every tone a distinct symbol, border style and label', () => {
    const descriptors = [
      describeVerdict('safe', 'completed'),
      describeVerdict('suspicious', 'completed'),
      describeVerdict('dangerous', 'completed'),
      describeVerdict('inconclusive', 'inconclusive'),
      describeVerdict('unknown', 'failed'),
    ];

    const symbols = descriptors.map((d) => d.symbol);
    const borders = descriptors.map((d) => d.borderStyle);
    const labels = descriptors.map((d) => d.label);

    expect(new Set(symbols).size).toBe(symbols.length);
    expect(new Set(borders).size).toBe(borders.length);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it('never claims that a safe result is guaranteed', () => {
    const descriptor = describeVerdict('safe', 'completed');
    expect(descriptor.description.toLowerCase()).toContain('not a guarantee');
    expect(descriptor.description.toLowerCase()).not.toContain('100%');
  });

  it('warns against entering data for a dangerous result', () => {
    const descriptor = describeVerdict('dangerous', 'completed');
    expect(descriptor.description.toLowerCase()).toContain('credentials');
  });
});

describe('<VerdictBadge />', () => {
  it('renders the label and symbol as text, not colour alone', () => {
    render(<VerdictBadge classification="dangerous" status="completed" />);
    expect(screen.getByText('Dangerous')).toBeInTheDocument();
    expect(screen.getByText('⛔')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveClass('verdict--dangerous');
  });

  it('shows the failed treatment when the status is failed', () => {
    render(<VerdictBadge classification="safe" status="failed" />);
    expect(screen.getByText('Analysis failed')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveClass('verdict--failed');
    expect(screen.getByRole('status')).not.toHaveClass('verdict--safe');
  });

  it('applies the border style that distinguishes the tone without colour', () => {
    render(<VerdictBadge classification="safe" status="completed" />);
    expect(screen.getByRole('status')).toHaveStyle({ borderStyle: 'solid' });
  });
});
