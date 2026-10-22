/**
 * The "Verify a website" page: input form + result panel + feedback control.
 */

import { useState } from 'react';
import ScanForm from '../components/ScanForm';
import ScanResultPanel from '../components/ScanResultPanel';
import { submitFeedback, submitScan } from '../services/api';
import type { ScanResult } from '../types';

interface ScanPageProps {
  onScanned?: () => void;
}

export default function ScanPage({ onScanned }: ScanPageProps) {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [feedbackState, setFeedbackState] = useState<string | null>(null);

  async function handleSubmit(url: string) {
    setIsLoading(true);
    setError(null);
    setFeedbackState(null);

    const response = await submitScan(url);

    if (response.ok) {
      setResult(response.data);
      onScanned?.();
    } else {
      setResult(null);
      setError(response.message);
    }
    setIsLoading(false);
  }

  async function handleFeedback(isCorrect: boolean) {
    if (!result) return;
    const response = await submitFeedback({
      scan_id: result.scan_id,
      is_correct: isCorrect,
    });
    setFeedbackState(
      response.ok
        ? 'Thank you - your feedback was recorded.'
        : `Feedback could not be recorded: ${response.message}`,
    );
  }

  return (
    <div className="page">
      <section className="panel panel--hero">
        <h2 className="panel__title">Verify a website before you trust it</h2>
        <p className="panel__note">
          Paste the address you are about to visit. PhishGuard extracts 35 structural features
          from the address and classifies it with a supervised model that was trained and
          evaluated on a labelled dataset of real URLs.
        </p>
        <ScanForm onSubmit={handleSubmit} isLoading={isLoading} />
      </section>

      {error ? (
        <div className="panel panel--error" role="alert" data-testid="scan-error">
          <h3 className="panel__title">The scan could not be performed</h3>
          <p>{error}</p>
          <p className="panel__note">
            No verdict was produced. The address has <strong>not</strong> been judged safe.
          </p>
        </div>
      ) : null}

      {result ? (
        <>
          <ScanResultPanel result={result} />
          <section className="panel" aria-labelledby="feedback-heading">
            <h2 id="feedback-heading" className="panel__title">
              Was this result helpful?
            </h2>
            <p className="panel__note">
              Feedback is stored with the scan record and is used to improve the model. It never
              changes the verdict you were shown.
            </p>
            <div className="button-row">
              <button
                type="button"
                className="button button--ghost"
                onClick={() => handleFeedback(true)}
                disabled={feedbackState !== null}
              >
                Yes, the verdict looks right
              </button>
              <button
                type="button"
                className="button button--ghost"
                onClick={() => handleFeedback(false)}
                disabled={feedbackState !== null}
              >
                No, the verdict looks wrong
              </button>
            </div>
            {feedbackState ? (
              <p className="panel__meta" role="status" data-testid="feedback-state">
                {feedbackState}
              </p>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
}
