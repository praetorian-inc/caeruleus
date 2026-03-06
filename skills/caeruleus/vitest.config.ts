import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['**/__tests__/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['lib/**/*.ts', '*.ts'],
      exclude: ['**/__tests__/**', 'vitest.config.ts'],
    },
  },
});
