import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node', // Ensure tests run in Node.js environment
    setupFiles: [], // No specific setup file needed for now
    globals: true, // Make Vitest APIs globally available
    // Use `define` to ensure `import.meta.env` is correctly populated during tests.
    // This is the recommended way to handle environment variables with Vite/Vitest.
    define: {
      'import.meta.env.NODE_ENV': JSON.stringify('development'),
      'import.meta.env.POW_SECRET': JSON.stringify('test-secret-for-vitest-environment-32-chars-min'),
    },
  },
});