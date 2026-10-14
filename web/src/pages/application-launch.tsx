import { useEffect, useRef, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { launchApplication, safeApplicationPath, safeApplicationReturn } from '@/lib/application-launch'

export default function ApplicationLaunch() {
  const { id = '' } = useParams()
  const [search] = useSearchParams()
  const [error, setError] = useState('')
  const started = useRef(false)
  useEffect(() => {
    if (started.current) return
    started.current = true
    try { void launchApplication(id, safeApplicationPath(search.get('path'))).catch(reason => setError(reason instanceof Error ? reason.message : 'Application could not open')) } catch (reason) { setError(reason instanceof Error ? reason.message : 'Invalid application destination') }
  }, [id, search])
  return <div className="p-6 text-text-primary">{error ? <p role="alert">{error} <a href={`/login?returnTo=${encodeURIComponent(safeApplicationReturn(`/applications/${id}/launch?${search.toString()}`))}`}>Sign in again</a></p> : <p>Opening application…</p>}</div>
}
