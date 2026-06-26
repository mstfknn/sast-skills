import { select, multiselect, isCancel } from '@clack/prompts';

export async function clackPrompt({ message, choices, multi }) {
  // Accept either bare ids or pre-built { value, label } option objects.
  const options = choices.map((c) => (typeof c === 'string' ? { value: c } : c));
  const value = multi
    ? await multiselect({ message, options, required: true })
    : await select({ message, options });
  if (isCancel(value)) {
    throw new Error('Prompt cancelled by user');
  }
  return value;
}
