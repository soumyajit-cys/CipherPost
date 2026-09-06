/**
 * API client entry point.
 *
 * Switch backends with one line:
 *   export const api: ApiClient = mockClient   // fixture data, no backend needed
 *   export const api: ApiClient = httpClient   // live FastAPI backend at /api/v1
 *
 * The active mode is also controllable at build/runtime via
 * `VITE_API_MODE` (values: "mock" | "http"). The mock is the default so the
 * dashboard is immediately demoable without a running backend.
 */
import type { ApiClient } from './types'
import { mockClient } from './mock/client'
import { httpClient } from './http/client'

const mode: 'mock' | 'http' =
  (import.meta.env.VITE_API_MODE === 'http' ? 'http' : 'mock')

export const api: ApiClient = mode === 'http' ? httpClient : mockClient
export const API_MODE = mode
export type { ApiClient }
export * from './types'