import { spawnSync } from 'child_process'
import path from 'path'

function run(cmd: string, args: string[], options?: { cwd?: string }) {
  const result = spawnSync(cmd, args, { stdio: 'inherit', ...options })
  if (result.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed with code ${result.status}`)
}

export default async function globalSetup() {
  const containerName = 'veyport-e2e'
  const httpPort = process.env.E2E_HTTP_PORT || '18081'
  const imageName = process.env.E2E_IMAGE || 'veyport-e2e:test'
  const repoRoot = path.resolve(__dirname, '../..')

  // Build if no pre-built image provided
  if (!process.env.E2E_IMAGE) {
    console.log('Building Docker image...')
    run('docker', ['build', '-t', 'veyport-e2e:test', '.'], { cwd: repoRoot })
  }

  // Remove old container
  spawnSync('docker', ['rm', '-f', containerName], { stdio: 'pipe' })

  // Start container
  console.log('Starting container...')
  run('docker', [
    'run', '-d',
    '--name', containerName,
    '-p', `${httpPort}:8081`,
    imageName,
    '--addr', ':8081',
    '--grpc-addr', ':9090',
    '--db', '/data/veyport.db',
    '--agent-bin-dir', '/app',
    '--grpc-external-addr', 'localhost:9443',
  ])

  // Wait for ready
  const baseURL = `http://localhost:${httpPort}`
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch(`${baseURL}/api/auth/status`)
      if (res.ok) {
        console.log(`Container ready after ${i + 1}s`)
        return
      }
    } catch { /* not ready */ }
    await new Promise(r => setTimeout(r, 1000))
  }
  throw new Error('Container not ready after 30s')
}
