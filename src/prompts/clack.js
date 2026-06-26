import { select, multiselect, isCancel } from '@clack/prompts';

export async function clackPrompt({ name, choices, multi }) {
  const options = choices.map((value) => ({ value }));
  const value = multi
    ? await multiselect({ message: name, options, required: false })
    : await select({ message: name, options });
  if (isCancel(value)) {
    throw new Error('Prompt cancelled by user');
  }
  return value;
}
