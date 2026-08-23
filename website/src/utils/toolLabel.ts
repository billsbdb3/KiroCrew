/**
 * Deterministic tool-label language guard.
 *
 * A tool call's "purpose" is model-authored prose (the agent's one-line
 * description of what the call does). The dashboard shows it as the tool-pill
 * label when the user has `simplifiedToolNames` on, and it is persisted
 * verbatim into session history. The agent writes it in whatever UI language
 * was active at the time and only follows the `[UI LANGUAGE]` steer on a
 * best-effort basis, so a transcript can end up holding purposes in a language
 * that no longer matches the user's current interface (e.g. Chinese labels
 * lingering after the user switched the dashboard to English).
 *
 * Rather than trust the model, we decide at RENDER time whether a saved purpose
 * is written in a script compatible with the active UI language. When it is
 * not, callers fall back to the language-neutral raw tool label (the same thing
 * shown when `simplifiedToolNames` is off) so the user never sees
 * foreign-script prose. This is deterministic and history-safe: it corrects old
 * frozen labels and newly-written ones alike, with no dependency on model
 * compliance.
 *
 * SCOPE: the guard operates at the level of WRITING SYSTEM (script), which is
 * all that can be detected reliably from a short string. It catches the jarring
 * cases — CJK / Hangul / Cyrillic / Devanagari / Bengali prose under a
 * Latin-script UI, and vice versa. It cannot distinguish two languages that
 * share the Latin script (e.g. an English purpose under a German UI); those
 * pass through unchanged.
 */

type Script = 'latin' | 'han' | 'kana' | 'hangul' | 'cyrillic' | 'devanagari' | 'bengali'

/** "Hard" (non-Latin) scripts whose mere presence unambiguously signals a
 *  specific language family. Latin is treated as the neutral default and is
 *  not listed here. */
const HARD_SCRIPT_RANGES: Record<Exclude<Script, 'latin'>, RegExp> = {
  han: /[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF]/,
  kana: /[\u3040-\u30FF]/,
  hangul: /[\uAC00-\uD7AF\u1100-\u11FF]/,
  cyrillic: /[\u0400-\u04FF]/,
  devanagari: /[\u0900-\u097F]/,
  bengali: /[\u0980-\u09FF]/,
}

/** A Latin letter (ASCII + Latin-1 Supplement / Extended-A accented forms). */
const LATIN_LETTER = /[A-Za-z\u00C0-\u024F]/

/** Expected script(s) for a resolved UI language tag. Matches on the primary
 *  subtag, so `zh-CN`, `zh-TW`, `pt-BR` etc. all resolve correctly. Anything
 *  unknown falls back to Latin, which is the safe default (it only ever
 *  suppresses clearly-foreign hard-script prose). */
function expectedScripts(lang: string): Set<Script> {
  const primary = (lang || '').toLowerCase().split('-')[0]
  switch (primary) {
    case 'zh':
      return new Set<Script>(['han'])
    case 'ja':
      return new Set<Script>(['han', 'kana'])
    case 'ko':
      return new Set<Script>(['hangul'])
    case 'ru':
      return new Set<Script>(['cyrillic'])
    case 'hi':
      return new Set<Script>(['devanagari'])
    case 'bn':
      return new Set<Script>(['bengali'])
    // en, es, fr, pt, de, it, and any unrecognized tag → Latin.
    default:
      return new Set<Script>(['latin'])
  }
}

/**
 * True when `text` is written in a script compatible with the UI language
 * `lang`. Empty / script-neutral text (a bare path, a tool identifier, digits
 * and punctuation only) is always considered compatible — there is nothing to
 * suppress.
 */
export function labelMatchesLanguage(text: string, lang: string): boolean {
  if (!text) return true
  const expected = expectedScripts(lang)

  // Which hard (non-Latin) scripts actually appear in the text?
  const present: Exclude<Script, 'latin'>[] = []
  for (const key of Object.keys(HARD_SCRIPT_RANGES) as Exclude<Script, 'latin'>[]) {
    if (HARD_SCRIPT_RANGES[key].test(text)) present.push(key)
  }

  // Forward mismatch: any hard script present that the UI language does not
  // expect (Han/Hangul/Cyrillic/... prose while the UI is, say, English). A
  // Latin tool identifier mixed into a Chinese purpose still carries Han
  // characters, so a genuine same-language purpose is never suppressed.
  for (const s of present) {
    if (!expected.has(s)) return false
  }

  // Reverse mismatch: a non-Latin UI language expects its own script, so
  // purely Latin/neutral prose (English written while the UI is Chinese) does
  // not match. Only trips when the text actually contains Latin letters, so a
  // script-neutral path/identifier still passes.
  const uiIsNonLatin = !expected.has('latin')
  if (uiIsNonLatin) {
    const hasExpectedScript = present.some(s => expected.has(s))
    if (!hasExpectedScript && LATIN_LETTER.test(text)) return false
  }

  return true
}

/**
 * Choose the text a tool pill / session-row / approval bar should display.
 *
 * - Raw mode (`simplified` off): always the raw tool label.
 * - Simplified mode: the agent's `purpose`, UNLESS its script does not match
 *   the active UI language, in which case fall back to `rawLabel` so the user
 *   never sees prose in a language other than their interface.
 */
export function pickToolLabel(opts: {
  simplified: boolean
  purpose?: string | null
  rawLabel: string
  uiLang: string
}): string {
  const { simplified, purpose, rawLabel, uiLang } = opts
  const trimmed = (purpose ?? '').trim()
  if (!simplified || !trimmed) return rawLabel
  return labelMatchesLanguage(trimmed, uiLang) ? trimmed : rawLabel
}

/** Raw shell titles stay readable until they become transcript-sized payloads.
 *  Beyond that point, show a stable technical summary and leave the exact
 *  command in ToolDetails. The summary deliberately uses executable names and
 *  symbols rather than generated prose: it stays language-neutral and cannot
 *  claim intent the command itself does not prove. */
const MAX_INLINE_SHELL_LABEL = 120
const MAX_SUMMARY_TOOLS = 2
const SHELL_WRAPPER_RE = /^(?:Running:\s*)?(?:\/[^\s]+\/)?(?:ba|z|fi)?sh\s+-lc\s+/
const PATH_RE = /(?:[A-Za-z]:[\\/]|\/|(?:\.{1,2}[\\/])?)(?:[\w@.+-]+[\\/])+[\w@.+-]+\.[A-Za-z0-9]+/g
const MULTIWORD_TOOLS = new Set(['cargo', 'git', 'go', 'npm', 'pnpm', 'yarn'])
const SHELL_BUILTINS = new Set(['cd', 'command', 'env', 'export', 'sudo'])

function commandFromInput(input: string, rawLabel: string): string {
  if (input) {
    try {
      const parsed = JSON.parse(input) as unknown
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const obj = parsed as Record<string, unknown>
        for (const key of ['command', 'cmd', 'script']) {
          if (typeof obj[key] === 'string' && obj[key]) return obj[key]
        }
      }
    } catch {
      // Plain-text tool inputs are already commands.
      return input
    }
  }

  const withoutWrapper = rawLabel.replace(SHELL_WRAPPER_RE, '').trim()
  if (
    withoutWrapper.length >= 2 &&
    ((withoutWrapper.startsWith('"') && withoutWrapper.endsWith('"')) ||
      (withoutWrapper.startsWith("'") && withoutWrapper.endsWith("'")))
  ) {
    return withoutWrapper.slice(1, -1)
  }
  return withoutWrapper
}

/** Split only at top-level command boundaries. Pipes stay inside a step because
 *  a pipeline is one operation in the activity stream, while `;`, newlines,
 *  `&&`, and `||` start the next operation. */
function splitShellSteps(command: string): string[] {
  const steps: string[] = []
  let start = 0
  let quote = ''
  let escaped = false

  const push = (end: number) => {
    const step = command.slice(start, end).trim()
    if (step) steps.push(step)
  }

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]
    if (escaped) {
      escaped = false
      continue
    }
    if (ch === '\\' && quote !== "'") {
      escaped = true
      continue
    }
    if (quote) {
      if (ch === quote) quote = ''
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch
      continue
    }

    const pair = command.slice(i, i + 2)
    if (ch === ';' || ch === '\n' || pair === '&&' || pair === '||') {
      push(i)
      i += pair === '&&' || pair === '||' ? 1 : 0
      start = i + 1
    }
  }
  push(command.length)
  return steps
}

function shellWords(step: string): string[] {
  return step.match(/(?:[^\s"'`]+|"[^"]*"|'[^']*'|`[^`]*`)+/g) ?? []
}

function toolName(step: string): string {
  const words = shellWords(step)
  let i = 0
  while (i < words.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i]) || SHELL_BUILTINS.has(words[i]))) i++
  if (i >= words.length) return ''

  const executable = words[i].replace(/^['"]|['"]$/g, '').split(/[\\/]/).pop() ?? ''
  if (!executable) return ''
  if (!MULTIWORD_TOOLS.has(executable)) return executable

  const subcommand = words.slice(i + 1).find(word => !word.startsWith('-'))
  return subcommand ? `${executable} ${subcommand.replace(/^['"]|['"]$/g, '')}` : executable
}

function singleTarget(command: string): string {
  const matches = command.match(PATH_RE) ?? []
  const basenames = new Set(
    matches.map(path => path.split(/[\\/]/).pop()).filter((name): name is string => !!name),
  )
  return basenames.size === 1 ? [...basenames][0] : ''
}

export function shellToolLabelNeedsCompaction(rawLabel: string): boolean {
  return rawLabel.includes('\n') || rawLabel.length > MAX_INLINE_SHELL_LABEL
}

export function compactShellToolLabel(rawLabel: string, input = ''): string {
  if (!shellToolLabelNeedsCompaction(rawLabel)) return rawLabel

  const command = commandFromInput(input, rawLabel)
  const steps = splitShellSteps(command)
  const tools = [...new Set(steps.map(toolName).filter(Boolean))]
  if (!tools.length) return `${rawLabel.slice(0, MAX_INLINE_SHELL_LABEL - 1).trimEnd()}…`

  const shownTools = tools.slice(0, MAX_SUMMARY_TOOLS)
  let summary = shownTools.join(' + ')
  if (tools.length > shownTools.length) summary += ` +${tools.length - shownTools.length}`
  if (steps.length > 1) summary += ` ×${steps.length}`

  const target = singleTarget(command)
  if (target) summary += ` · ${target}`
  return summary.length > MAX_INLINE_SHELL_LABEL
    ? `${summary.slice(0, MAX_INLINE_SHELL_LABEL - 1).trimEnd()}…`
    : summary
}

export function pickCompactToolLabel(opts: {
  simplified: boolean
  purpose?: string | null
  rawLabel: string
  uiLang: string
  isShell: boolean
  input?: string
}): string {
  const picked = pickToolLabel(opts)
  // A compatible agent-written purpose is already the best concise summary.
  if (!opts.isShell || picked !== opts.rawLabel) return picked
  return compactShellToolLabel(picked, opts.input)
}
