/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Base URL of the PhishGuard API.  Empty (the default) means "same origin",
   * which is what the Vite dev-server proxy expects.
   */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
