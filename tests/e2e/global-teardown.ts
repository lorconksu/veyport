import { spawnSync } from 'child_process'

export default async function globalTeardown() {
  spawnSync('docker', ['rm', '-f', 'veyport-e2e'], { stdio: 'pipe' })
}
