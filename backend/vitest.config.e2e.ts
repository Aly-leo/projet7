import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

const plugin = swc.vite({
  module: { type: 'es6' },
  jsc: {
    target: 'es2022',
    parser: { syntax: 'typescript', decorators: true },
    transform: { legacyDecorator: true, decoratorMetadata: true },
  },
});

export default defineConfig({
  plugins: [plugin],
  test: {
    globals: true,
    root: './',
    include: ['test/**/*.e2e-spec.ts'],
    globalSetup: ['./test/global-setup.ts'],
    testTimeout: 90_000,
    hookTimeout: 180_000,
    env: {
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://postgres:postgres@localhost:1/none',
      JWT_ACCESS_SECRET: 'test-secret-test-secret-test-secret-test-secret-0123456789',
      APP_ORIGIN: 'http://localhost:4200',
      MAX_IMPORT_MB: '1',
      MAX_ALERTS_PER_IMPORT: '5000',
      REPORT_MAX_FINDINGS: '500',
      PREDICTION_PROVIDER: 'rules',
    },
  },
});
