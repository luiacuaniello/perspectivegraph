/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Bearer token the dashboard sends when the backend API is secured. */
  readonly VITE_API_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
