import { describe, it, expect } from 'vitest'
import { isPlanAction } from '../hooks/usePlanActionMutation'

/* The allowlist must mirror the server's plan-action contract exactly:
 * chat_orchestrator lowercases and strips the incoming action and accepts
 * only 'go', 'go all', 'cancel'. isPlanAction applies the same normalization
 * client-side, so every label it admits is a label the server will act on,
 * and everything else stays on the composer path. */

describe('isPlanAction', () => {
  it.each(['Go', 'Go All', 'Cancel'])('accepts the canonical chip label %j', (label) => {
    expect(isPlanAction(label)).toBe(true)
  })

  it.each(['go', 'GO', 'go all', 'GO ALL', 'cancel', 'CANCEL'])(
    'is case-insensitive, matching the server\'s .lower(): %j', (label) => {
      expect(isPlanAction(label)).toBe(true)
    })

  it.each([' Go ', '\tCancel\n', ' go all '])(
    'trims surrounding whitespace, matching the server\'s .strip(): %j', (label) => {
      expect(isPlanAction(label)).toBe(true)
    })

  it.each(['Approve', 'Approve it', 'Stage-1-APPROVE', 'Go  All', 'goall', 'go-all', '', ' '])(
    'rejects non-protocol labels the server would 400: %j', (label) => {
      expect(isPlanAction(label)).toBe(false)
    })
})
