import { defineConfig } from 'vitest/config'

// Pure-logic + fixture-grounded tests for the deep-link codecs, the tour
// placement/anchor helpers, and the scenario validator. These run in Node with no
// DOM and no React transform, so this config carries no plugins. Kept out of every
// tsconfig `include`, so `tsc -b` (the production build) never compiles it.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
})
