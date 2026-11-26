import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, test } from '@playwright/test'
import { withEnrolledAgent } from './enrolled-agent'

const imageName = 'e2e-preview.png'
const dimensions = { width: 1024, height: 1024 }

test.use({ actionTimeout: 15_000, trace: 'off', viewport: { width: 1280, height: 720 } })

test('previews and downloads a remote image', { tag: '@smoke' }, async ({ page }) => {
  test.setTimeout(120_000)
  const encoded = await page.evaluate(({ width, height }) => {
    const canvas = document.createElement('canvas')
    canvas.width = width
    canvas.height = height
    const context = canvas.getContext('2d')!
    const pixels = context.createImageData(width, height)
    // Noise keeps the compressed PNG above the 1 MiB text-tail size.
    const rowSize = width * 4
    for (let offset = 0; offset < pixels.data.length; offset += rowSize) {
      crypto.getRandomValues(pixels.data.subarray(offset, offset + rowSize))
    }
    context.putImageData(pixels, 0, 0)
    return canvas.toDataURL('image/png').slice('data:image/png;base64,'.length)
  }, dimensions)
  const png = Buffer.from(encoded, 'base64')
  expect(png.length).toBeGreaterThan(1024 * 1024)

  const directory = await mkdtemp(join(tmpdir(), 'veyport-preview-e2e-'))
  try {
    const source = join(directory, imageName)
    await writeFile(source, png, { mode: 0o644 })
    await withEnrolledAgent(page, { source, name: imageName }, async serverURL => {
      await page.goto(serverURL)
      await page.getByRole('button', { name: 'Files', exact: true }).click()
      await page.getByRole('button', { name: '/', exact: true }).click()
      await page.getByRole('button', { name: imageName, exact: true }).click()

      const viewer = page.getByRole('region', { name: 'Image preview' })
      const image = viewer.getByRole('img', { name: imageName })
      await expect(image).toBeVisible({ timeout: 15_000 })
      await expect(image).toHaveJSProperty('naturalWidth', dimensions.width)
      await expect(image).toHaveJSProperty('naturalHeight', dimensions.height)

      const fit = viewer.getByRole('button', { name: 'Fit to window' })
      const actual = viewer.getByRole('button', { name: 'Actual size' })
      const width = () => image.evaluate(el => el.getBoundingClientRect().width)
      await expect(fit).toHaveAttribute('aria-pressed', 'true')
      expect(await width()).toBeLessThan(dimensions.width)
      await actual.click()
      await expect(actual).toHaveAttribute('aria-pressed', 'true')
      await expect.poll(width).toBe(dimensions.width)
      await fit.click()
      await expect.poll(width).toBeLessThan(dimensions.width)

      const [download] = await Promise.all([
        page.waitForEvent('download'),
        viewer.getByRole('link', { name: 'Download' }).click(),
      ])
      expect(download.suggestedFilename()).toBe(imageName)
      expect((await readFile(await download.path())).equals(png), 'download matches the remote PNG').toBe(true)

      await viewer.getByRole('button', { name: 'Close' }).click()
      await expect(viewer).toHaveCount(0)
      await expect(page.getByText('Select a file to view its contents')).toBeVisible()
    })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
