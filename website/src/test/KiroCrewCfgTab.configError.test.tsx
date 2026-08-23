/**
 * The adapter card must survive a failed config load.
 *
 * Found by using the real UI: the Config tab showed "Failed to fetch" and every
 * control vanished with it, including the ACP adapter card. That tab is the only
 * place an adapter can be switched, so a transient failure — a gateway restart
 * under an open tab, a dropped connection, an expired session — removed the one
 * control an operator needs, and the remaining remedy was editing config.json on
 * the host. It matters most in exactly the case where switching back IS the fix.
 *
 * The card reads /api/acp-backends and nothing from the config query, so there is
 * no reason for one to take out the other.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const mocks = vi.hoisted(() => ({
  onSave: null as null | ((path: string, value: string) => Promise<void> | void),
  patchConfig: vi.fn(),
}))

vi.mock('../pages/overview/AcpBackendCard', () => ({
  AcpBackendCard: ({ onSave }: { onSave: (path: string, value: string) => Promise<void> | void }) => {
    mocks.onSave = onSave
    return <div data-testid="acp-card">adapter card</div>
  },
}))

vi.mock('../hooks/usePreviewFlag', () => ({
  usePreviewFlag: () => true,
}))

vi.mock('../api/client', () => ({
  api: {
    // The failure mode observed in the browser: fetch rejects at the network
    // layer, so the message is a TypeError string rather than an HTTP body.
    kirocrewConfig: () => Promise.reject(new Error('Failed to fetch')),
    patchConfig: mocks.patchConfig,
  },
}))

vi.mock('../hooks/useProvider', () => ({
  useProvider: () => ({ labels: { agentTemplateField: 'Agent' } }),
}))

let KiroCrewCfgTab: React.ComponentType

beforeEach(async () => {
  vi.resetModules()
  mocks.onSave = null
  mocks.patchConfig.mockReset()
  mocks.patchConfig.mockResolvedValue({})
  KiroCrewCfgTab = (await import('../pages/overview/KiroCrewCfgTab')).default
})

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <KiroCrewCfgTab />
    </QueryClientProvider>,
  )
}

describe('KiroCrewCfgTab with a failed config query', () => {
  it('still renders the adapter card', async () => {
    mount()
    await waitFor(() => expect(screen.getByTestId('acp-card')).toBeTruthy())
  })

  it('still surfaces the error rather than hiding it', async () => {
    mount()
    await waitFor(() => expect(screen.getByText(/Failed to fetch/)).toBeTruthy())
  })

  it('keeps the adapter save pending until the config PATCH completes', async () => {
    let resolvePatch: (value: object) => void = () => undefined
    mocks.patchConfig.mockReturnValue(
      new Promise(resolve => {
        resolvePatch = resolve
      }),
    )
    mount()
    await waitFor(() => expect(mocks.onSave).not.toBeNull())

    const pending = mocks.onSave!('agent.acp_backend', 'codex')
    expect(pending).toBeInstanceOf(Promise)
    let settled = false
    void Promise.resolve(pending).then(() => {
      settled = true
    })
    await Promise.resolve()
    expect(settled).toBe(false)

    resolvePatch({})
    await pending
    expect(settled).toBe(true)
  })
})
