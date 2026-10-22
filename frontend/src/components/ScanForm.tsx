/**
 * URL input + "Check this website" button.
 *
 * The form performs local validation first (so the user gets immediate,
 * readable feedback) and then calls the backend, which remains the
 * authoritative validator.  A loading state is exposed through
 * `aria-busy` and a visible spinner label.
 */

import { useState } from 'react';
import { validateUrlInput } from '../services/api';

interface ScanFormProps {
  onSubmit: (url: string) => void;
  isLoading: boolean;
  disabled?: boolean;
}

export default function ScanForm({ onSubmit, isLoading, disabled = false }: ScanFormProps) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState<string | null>(null);

  function handleChange(event: React.ChangeEvent<HTMLInputElement>) {
    setUrl(event.target.value);
    if (error) setError(null);
  }

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (isLoading) return;

    const trimmed = url.trim();
    const validationError = validateUrlInput(trimmed);
    if (validationError) {
      setError(validationError);
      return;
    }
    setError(null);
    onSubmit(trimmed);
  }

  const errorId = 'scan-url-error';

  return (
    <form className="scan-form" onSubmit={handleSubmit} noValidate aria-busy={isLoading}>
      <label className="scan-form__label" htmlFor="scan-url">
        Website address to verify
      </label>
      <p className="scan-form__help" id="scan-url-help">
        Enter the full address including <code>https://</code>. The address is analysed, never
        opened automatically.
      </p>
      <div className="scan-form__row">
        <input
          id="scan-url"
          name="url"
          type="text"
          className={`scan-form__input${error ? ' scan-form__input--invalid' : ''}`}
          placeholder="https://example.com/login"
          value={url}
          onChange={handleChange}
          aria-invalid={error ? 'true' : 'false'}
          aria-describedby={error ? `${errorId} scan-url-help` : 'scan-url-help'}
          autoComplete="url"
          spellCheck={false}
          disabled={isLoading || disabled}
        />
        <button
          type="submit"
          className="button button--primary"
          disabled={isLoading || disabled}
        >
          {isLoading ? 'Analysing…' : 'Check this website'}
        </button>
      </div>

      {error ? (
        <p className="scan-form__error" id={errorId} role="alert" data-testid="input-error">
          {error}
        </p>
      ) : null}

      {isLoading ? (
        <p className="scan-form__loading" role="status" data-testid="loading">
          <span className="spinner" aria-hidden="true" />
          Analysing the address with the trained model. This usually takes a few milliseconds.
        </p>
      ) : null}
    </form>
  );
}
