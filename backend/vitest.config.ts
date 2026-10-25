import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// SWC fournit les métadonnées de décorateurs nécessaires à l'injection de dépendances de NestJS.
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
    include: ['src/**/*.spec.ts'],
    env: {
      NODE_ENV: 'test',
      DATABASE_URL: 'postgresql://postgres:postgres@localhost:1/none',
      JWT_ACCESS_SECRET: 'test-secret-test-secret-test-secret-test-secret-0123456789',
    },
  },
});
