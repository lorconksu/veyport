interface LogoProps {
  layout?: 'vertical' | 'horizontal'
  mode?: 'light' | 'dark'
  className?: string
}

const logoSources = {
  dark: {
    horizontal: '/veyport-dark-horizontal.png',
    vertical: '/veyport-dark-vertical.png',
  },
  light: {
    horizontal: '/veyport-horizontal.png',
    vertical: '/veyport-vertical.png',
  },
} as const

function logoClassName(defaultWidth: string, className: string): string {
  const hasWidthOverride = /(?:^|\s)(?:[a-z-]+:)*!?w-/.test(className)
  return [hasWidthOverride ? '' : defaultWidth, 'h-auto', className].filter(Boolean).join(' ')
}

export function Logo({ layout = 'horizontal', mode = 'dark', className = '' }: Readonly<LogoProps>) {
  if (layout === 'vertical') {
    return (
      <img
        src={logoSources[mode].vertical}
        alt="Veyport"
        className={logoClassName('w-20', className)}
      />
    )
  }

  return (
    <img
      src={logoSources[mode].horizontal}
      alt="Veyport"
      className={logoClassName('w-28', className)}
    />
  )
}
