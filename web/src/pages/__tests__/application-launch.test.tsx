import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { vi, it, expect } from 'vitest'
import ApplicationLaunch from '../application-launch'
import { launchApplication } from '@/lib/application-launch'
vi.mock('@/lib/application-launch', async importOriginal => ({ ...await importOriginal<typeof import('@/lib/application-launch')>(), launchApplication: vi.fn() }))
it('launches the validated direct link once', async () => {
  vi.mocked(launchApplication).mockResolvedValue()
  render(<MemoryRouter initialEntries={['/applications/abc/launch?path=%2Fnative']}><Routes><Route path="/applications/:id/launch" element={<ApplicationLaunch />} /></Routes></MemoryRouter>)
  expect(screen.getByText('Opening application…')).toBeInTheDocument()
  await waitFor(() => expect(launchApplication).toHaveBeenCalledWith('abc', '/native'))
})
it('shows a refused launch and a fresh login control', async () => {
  vi.mocked(launchApplication).mockRejectedValue(new Error('Sign in again'))
  render(<MemoryRouter initialEntries={['/applications/abc/launch']}><Routes><Route path="/applications/:id/launch" element={<ApplicationLaunch />} /></Routes></MemoryRouter>)
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Sign in again'))
})
