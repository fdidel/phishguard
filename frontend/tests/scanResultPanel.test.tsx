/**
 * The result panel is the user-facing safety surface.  These tests cover the
 * requirements that a failed scan is never presented as safe, that a dangerous
 * verdict explicitly warns against entering credentials or payment details,
 * and that the submitted address is never turned into a clickable link.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import ScanResultPanel from '../src/components/ScanResultPanel';
import { dangerousResult, failedResult, DANGEROUS_URL } from './fixtures';

describe('<ScanResultPanel />', () => {
  it('renders the submitted address as plain text and never as a link', () => {
    render(<ScanResultPanel result={dangerousResult()} />);

    const submitted = screen.getByTestId('submitted-url');
    expect(submitted).toHaveTextContent(DANGEROUS_URL);
    expect(submitted.tagName).toBe('P');

    // No anchor anywhere in the panel may point at the scanned host.
    const anchors = Array.from(document.querySelectorAll('a'));
    expect(anchors).toHaveLength(0);
    expect(
      anchors.filter((a) => (a.getAttribute('href') ?? '').includes('paypa1-secure-login')),
    ).toHaveLength(0);
  });

  it('shows the seven required result sections', () => {
    render(<ScanResultPanel result={dangerousResult()} />);

    expect(screen.getByText('Address you submitted')).toBeInTheDocument();
    expect(screen.getByText('Verdict')).toBeInTheDocument();
    expect(screen.getByText('Risk')).toBeInTheDocument();
    expect(screen.getByText('Why this verdict')).toBeInTheDocument();
    expect(screen.getByText('What was checked')).toBeInTheDocument();
    expect(screen.getByText('Model')).toBeInTheDocument();
    expect(screen.getByText('Limitations')).toBeInTheDocument();
  });

  it('warns against entering personal information for a dangerous verdict', () => {
    render(<ScanResultPanel result={dangerousResult()} />);

    const advice = screen.getByTestId('danger-advice');
    expect(advice).toBeInTheDocument();
    expect(advice.textContent?.toLowerCase()).toContain('do not enter');
    expect(advice.textContent?.toLowerCase()).toContain('password');
    expect(advice.textContent?.toLowerCase()).toContain('card details');
  });

  it('treats a failed scan as failed, never as safe', () => {
    render(<ScanResultPanel result={failedResult()} />);

    // The failed advice block is shown ...
    const advice = screen.getByTestId('failed-advice');
    expect(advice).toBeInTheDocument();
    expect(advice.textContent?.toLowerCase()).toContain('not');

    // ... the verdict badge is the failed one ...
    expect(screen.getByText('Analysis failed')).toBeInTheDocument();
    expect(document.querySelector('.verdict--safe')).toBeNull();

    // ... and the dangerous advice block is NOT shown.
    expect(screen.queryByTestId('danger-advice')).toBeNull();
  });

  it('never shows the dangerous advice block for a failed scan', () => {
    // Pathological case: a mis-wired backend claims "dangerous" on a failed run.
    render(<ScanResultPanel result={failedResult({ classification: 'dangerous' })} />);
    expect(screen.queryByTestId('danger-advice')).toBeNull();
    expect(screen.getByTestId('failed-advice')).toBeInTheDocument();
  });

  it('reports the analysis coverage so the user knows what was checked', () => {
    render(<ScanResultPanel result={dangerousResult()} />);
    expect(screen.getByTestId('analysis-coverage')).toHaveTextContent(
      'Only the URL structure was analysed',
    );
  });

  it('shows the model provenance', () => {
    render(<ScanResultPanel result={dangerousResult()} />);
    expect(screen.getByTestId('model-version')).toHaveTextContent('2026.10.22-0001');
  });

  it('lists the limitations that apply to the verdict', () => {
    render(<ScanResultPanel result={dangerousResult()} />);
    const limitations = screen.getByTestId('limitations');
    expect(limitations.textContent).toContain('only sees the structure');
  });

  it('separates per-prediction contributions from global feature importance', () => {
    render(<ScanResultPanel result={dangerousResult()} />);
    expect(screen.getByText('Top contributing features for this prediction')).toBeInTheDocument();
    expect(screen.getByTestId('explanation-note')).toBeInTheDocument();
    expect(
      screen.getByText(/does not by itself mean the feature triggered this particular verdict/i),
    ).toBeInTheDocument();
  });

  it('renders the risk score with an accessible meter', () => {
    render(<ScanResultPanel result={dangerousResult()} />);
    const meter = screen.getByRole('meter');
    expect(meter).toHaveAttribute('aria-valuenow', '91');
    expect(meter).toHaveAttribute('aria-valuemin', '0');
    expect(meter).toHaveAttribute('aria-valuemax', '100');
  });

  it('does not display a risk score when the analysis failed', () => {
    render(<ScanResultPanel result={failedResult()} />);
    expect(screen.queryByRole('meter')).toBeNull();
    expect(screen.getByText('Not available')).toBeInTheDocument();
  });

  it('renders the failure reason when a scan fails', () => {
    render(<ScanResultPanel result={failedResult()} />);

    // The failure reason block is shown only when error_code is present.
    expect(screen.getByTestId('failure-reason')).toBeInTheDocument();
    expect(screen.getByText('Why it failed')).toBeInTheDocument();
    expect(screen.getByText('UNSUPPORTED_SCHEME')).toBeInTheDocument();

    // The failure detail explains why the scan failed.
    expect(screen.getByTestId('failure-detail')).toBeInTheDocument();
    expect(screen.getByText(/only http and https URLs can be analysed/i)).toBeInTheDocument();
  });

  it('hides the failure reason when the scan did not fail', () => {
    render(<ScanResultPanel result={dangerousResult()} />);
    expect(screen.queryByTestId('failure-reason')).toBeNull();
    expect(screen.queryByTestId('failure-detail')).toBeNull();
  });
});
