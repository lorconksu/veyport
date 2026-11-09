import { spawnSync } from 'node:child_process'
import { ESLint } from 'eslint'
import { describe, expect, it } from 'vitest'

const webRoot = process.cwd()

describe('development dependency glob safety', () => {
  it('bounds globstar-parent preprocessing at optimization level 2', () => {
    // GHSA-g3hv-75wg-m249: 10.2.6 ignores this expansion budget during preprocessing.
    // Isolate amplification so a regression cannot hang or exhaust the Vitest worker.
    const result = spawnSync(process.execPath, ['--max-old-space-size=96', '-e', `
      const { Minimatch } = require('minimatch');
      const matcher = new Minimatch('**/../a/b/'.repeat(18) + 'target.ts', {
        optimizationLevel: 2,
        braceExpandMax: 64,
      });
      console.log(JSON.stringify({ alternatives: matcher.set.length }));
    `], { cwd: webRoot, encoding: 'utf8', timeout: 5000 })

    expect(result.error).toBeUndefined()
    expect(result.status, result.stderr).toBe(0)
    expect(JSON.parse(result.stdout).alternatives).toBe(64)
  })

  it('preserves ESLint TypeScript selection and generated-file ignores', async () => {
    const eslint = new ESLint({ cwd: webRoot })
    for (const filePath of ['src/dependency-glob-fixture.ts', 'src/nested/dependency-glob-fixture.tsx']) {
      const [result] = await eslint.lintText('export const answer: number = 42\n', { filePath })
      expect(result.messages).toEqual([])
    }
    expect(await eslint.isPathIgnored('dist/assets/generated.js')).toBe(true)
  })
})
