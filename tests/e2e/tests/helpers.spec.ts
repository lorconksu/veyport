import { test, expect } from '@playwright/test'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { mintApiToken } from './helpers'

test('API token helper passes shell metacharacters as literal Docker arguments', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'veyport-helper-'))
  const capturedArgs = path.join(directory, 'args.json')
  const marker = path.join(directory, 'injected')
  const previousPath = process.env.PATH
  const previousContainer = process.env.E2E_CONTAINER
  const container = `container; touch ${marker}; #`
  const username = 'user with spaces; $(false)'
  const name = 'token "quoted"; `false`'
  const expectedToken = 'adt_' + '0'.repeat(16)
  fs.writeFileSync(path.join(directory, 'docker'), `#!/usr/bin/env node
require('fs').writeFileSync(${JSON.stringify(capturedArgs)}, JSON.stringify(process.argv.slice(2)))
console.log(${JSON.stringify(`Token: ${expectedToken}`)})
`, { mode: 0o700 })
  process.env.PATH = `${directory}${path.delimiter}${previousPath ?? ''}`
  process.env.E2E_CONTAINER = container
  try {
    const token = await mintApiToken(username, name)
    expect(fs.existsSync(marker)).toBe(false)
    expect(token).toBe(expectedToken)
    expect(JSON.parse(fs.readFileSync(capturedArgs, 'utf8'))).toEqual([
      'exec', container, '/app/veyport', 'admin', 'create-api-token',
      '--db', '/data/veyport.db', '--username', username, '--name', name,
    ])
  } finally {
    if (previousPath === undefined) delete process.env.PATH
    else process.env.PATH = previousPath
    if (previousContainer === undefined) delete process.env.E2E_CONTAINER
    else process.env.E2E_CONTAINER = previousContainer
    fs.rmSync(directory, { recursive: true, force: true })
  }
})
