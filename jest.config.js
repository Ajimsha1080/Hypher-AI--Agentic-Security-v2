module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/src/tests/**/*.test.ts'],
  moduleNameMapper: {},
  globals: { 'ts-jest': { tsconfig: { strict: false, esModuleInterop: true } } },
  testTimeout: 15000,
};
