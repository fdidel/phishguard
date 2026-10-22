/**
 * The scan form performs client-side validation before it talks to the
 * backend.  These tests check that invalid input never reaches the API and
 * that the accessibility wiring for the error state is correct.
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ScanForm from '../src/components/ScanForm';

function renderForm(onSubmit = vi.fn(), isLoading = false) {
  render(<ScanForm onSubmit={onSubmit} isLoading={isLoading} />);
  return { onSubmit };
}

describe('<ScanForm />', () => {
  it('submits a valid address', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText(/website address to verify/i), 'https://example.com/login');
    await user.click(screen.getByRole('button', { name: /check this website/i }));

    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit).toHaveBeenCalledWith('https://example.com/login');
    expect(screen.queryByTestId('input-error')).toBeNull();
  });

  it('trims the address before submitting', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText(/website address to verify/i), '  https://example.com  ');
    await user.click(screen.getByRole('button', { name: /check this website/i }));

    expect(onSubmit).toHaveBeenCalledWith('https://example.com');
  });

  it('rejects an empty address without calling the API', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.click(screen.getByRole('button', { name: /check this website/i }));

    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByTestId('input-error')).toBeInTheDocument();
  });

  it('rejects an address without an http(s) scheme', async () => {
    const user = userEvent.setup();
    const { onSubmit } = renderForm();

    await user.type(screen.getByLabelText(/website address to verify/i), 'javascript:alert(1)');
    await user.click(screen.getByRole('button', { name: /check this website/i }));

    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByTestId('input-error').textContent).toMatch(/http:\/\/ or https:\/\//i);
  });

  it('marks the input invalid and links the error message for screen readers', async () => {
    const user = userEvent.setup();
    renderForm();

    await user.click(screen.getByRole('button', { name: /check this website/i }));

    const input = screen.getByLabelText(/website address to verify/i);
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input.getAttribute('aria-describedby')).toContain('scan-url-error');
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('clears the error as soon as the user edits the field', async () => {
    const user = userEvent.setup();
    renderForm();

    await user.click(screen.getByRole('button', { name: /check this website/i }));
    expect(screen.getByTestId('input-error')).toBeInTheDocument();

    await user.type(screen.getByLabelText(/website address to verify/i), 'h');
    expect(screen.queryByTestId('input-error')).toBeNull();
  });

  it('exposes a busy state while the scan is running', () => {
    renderForm(vi.fn(), true);

    const form = document.querySelector('form');
    expect(form).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByTestId('loading')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /analysing/i })).toBeDisabled();
    expect(screen.getByLabelText(/website address to verify/i)).toBeDisabled();
  });
});
