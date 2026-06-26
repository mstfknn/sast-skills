export function BANNER(version) {
  return [
    ' ██████╗  █████╗ ███████╗████████╗    ███████╗██╗  ██╗██╗██╗     ██╗     ██████╗',
    '██╔════╝ ██╔══██╗██╔════╝╚══██╔══╝    ██╔════╝██║ ██╔╝██║██║     ██║    ██╔════╝',
    '╚█████╗  ███████║╚█████╗    ██║       ███████╗█████╔╝ ██║██║     ██║    ╚█████╗ ',
    ' ╚═══██╗ ██╔══██║╚════██╗   ██║       ╚════██║██╔═██╗ ██║██║     ██║     ╚═══██╗',
    `██████╔╝ ██║  ██║███████║   ██║       ███████║██║  ██╗██║███████╗███████╗██████╔╝ v${version}`,
    '╚══════╝  ╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝',
    ' Turn your AI coding assistant into a SAST scanner',
    ' github.com/mstfknn/sast-skills · 36 skills, 32 classes',
    '',
  ].join('\n');
}

export function summaryText({ scope, labels, entryFiles, skillCount }) {
  const lines = [
    `Installed for ${labels.length} assistant${labels.length === 1 ? '' : 's'} (${scope}): ${labels.join(', ')}.`,
    `Wrote: ${entryFiles.join(', ')}  +  ${skillCount} skills.`,
    'Prompt your assistant: "Run vulnerability scan".',
  ];
  if (labels.includes('Aider')) {
    lines.push('Aider: add `--read CONVENTIONS.md` or set it in `.aider.conf.yml` so Aider loads it.');
  }
  return lines.join('\n');
}
