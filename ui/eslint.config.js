import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    rules: {
      // Opt out of react-hooks 7.1's new (React-Compiler-era) rule for now.
      // Our two effects that trip it are intentional: seeding editable local
      // state from an async query (the Settings form) and seeding a WebSocket
      // log buffer from the initial fetch. Adopting the rule means refactoring
      // core UI with real regression risk — tracked as a follow-up, not part of
      // the eslint 9->10 bump.
      'react-hooks/set-state-in-effect': 'off',
    },
  },
])
