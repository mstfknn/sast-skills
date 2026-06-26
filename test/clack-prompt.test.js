import { test, expect, vi } from 'vitest';

vi.mock('@clack/prompts', () => ({
  select: vi.fn(),
  multiselect: vi.fn(),
  isCancel: vi.fn().mockReturnValue(false),
}));

const clack = await import('@clack/prompts');
const { clackPrompt } = await import('../src/prompts/clack.js');

test('clackPrompt delegates to @clack/prompts.select with the given message and options', async () => {
  clack.select.mockResolvedValueOnce('agents');

  const result = await clackPrompt({ message: 'Install scope', choices: ['claude', 'agents', 'all'] });

  expect(result).toBe('agents');
  expect(clack.select).toHaveBeenCalledTimes(1);
  const call = clack.select.mock.calls[0][0];
  expect(call.message).toBe('Install scope');
  expect(call.options.map((o) => o.value)).toEqual(['claude', 'agents', 'all']);
});

test('clackPrompt throws a user-friendly error when the user cancels', async () => {
  const cancelToken = Symbol('cancel');
  clack.select.mockResolvedValueOnce(cancelToken);
  clack.isCancel.mockReturnValueOnce(true);

  await expect(
    clackPrompt({ message: 'Pick one', choices: ['claude', 'agents'] }),
  ).rejects.toThrow(/cancel/i);
});

test('clackPrompt uses a required multiselect and passes labeled options through', async () => {
  clack.multiselect = vi.fn().mockResolvedValueOnce(['claude', 'cursor']);
  const choices = [{ value: 'claude', label: 'Claude Code' }, { value: 'cursor', label: 'Cursor' }];

  const result = await clackPrompt({ message: 'Pick assistants', choices, multi: true });

  expect(result).toEqual(['claude', 'cursor']);
  const call = clack.multiselect.mock.calls[0][0];
  expect(call.required).toBe(true);
  expect(call.message).toBe('Pick assistants');
  expect(call.options).toEqual(choices);
});
