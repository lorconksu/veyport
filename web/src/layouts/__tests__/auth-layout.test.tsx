import { render, screen } from '@testing-library/react'
import { vi } from 'vitest'
import { AuthLayout } from '../auth-layout'

// Mock react-router-dom Outlet
vi.mock('react-router-dom', () => ({
  Outlet: () => <div data-testid="outlet">outlet content</div>,
}))

// Mock Logo component
vi.mock('@/components/logo', () => ({
  Logo: ({ layout, className }: { layout?: string; className?: string }) => (
    <img data-testid="logo" data-layout={layout} className={className} alt="Veyport" />
  ),
}))

describe('AuthLayout', () => {
  it('renders the Logo with vertical layout', () => {
    render(<AuthLayout />)
    const logo = screen.getByTestId('logo')
    expect(logo).toBeInTheDocument()
    expect(logo).toHaveAttribute('data-layout', 'vertical')
  })

  it('renders the Outlet', () => {
    render(<AuthLayout />)
    expect(screen.getByTestId('outlet')).toBeInTheDocument()
    expect(screen.getByText('outlet content')).toBeInTheDocument()
  })

  it('renders a container with min-h-screen class', () => {
    const { container } = render(<AuthLayout />)
    expect(container.firstChild).toHaveClass('min-h-screen')
  })
})
