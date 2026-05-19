import { render, screen } from '@testing-library/react'
import { Logo } from '../logo'

describe('Logo', () => {
  it('renders horizontal layout by default', () => {
    render(<Logo />)
    const img = screen.getByRole('img', { name: 'Veyport' })
    expect(img).toBeInTheDocument()
    expect(img).toHaveAttribute('src', '/veyport-dark-horizontal.png')
    expect(img.className).toContain('w-28')
  })

  it('renders horizontal layout when layout="horizontal"', () => {
    render(<Logo layout="horizontal" />)
    const img = screen.getByRole('img', { name: 'Veyport' })
    expect(img).toHaveAttribute('src', '/veyport-dark-horizontal.png')
    expect(img.className).toContain('w-28')
  })

  it('renders vertical layout when layout="vertical"', () => {
    render(<Logo layout="vertical" />)
    const img = screen.getByRole('img', { name: 'Veyport' })
    expect(img).toHaveAttribute('src', '/veyport-dark-vertical.png')
    expect(img.className).toContain('w-20')
  })

  it('renders light assets when mode="light"', () => {
    render(<Logo layout="horizontal" mode="light" />)
    const img = screen.getByRole('img', { name: 'Veyport' })
    expect(img).toHaveAttribute('src', '/veyport-horizontal.png')
  })

  it('passes additional className for horizontal layout', () => {
    render(<Logo layout="horizontal" className="extra-class" />)
    const img = screen.getByRole('img', { name: 'Veyport' })
    expect(img.className).toContain('extra-class')
  })

  it('passes additional className for vertical layout', () => {
    render(<Logo layout="vertical" className="w-40" />)
    const img = screen.getByRole('img', { name: 'Veyport' })
    expect(img.className).toContain('w-40')
  })

  it('has alt text "Veyport"', () => {
    render(<Logo />)
    expect(screen.getByAltText('Veyport')).toBeInTheDocument()
  })
})
