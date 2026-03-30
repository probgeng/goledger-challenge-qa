import { describe, it, expect } from 'vitest';

// These tests verify bugs by analyzing the source code directly.
// They read the actual function implementations to confirm the bugs exist.

describe('BUG-009: createBook() missing Authorization header', () => {
  it('should include Authorization header in createBook', async () => {
    // Read the source code of createBook
    const apiModule = await import('./api?raw');
    const source = (apiModule as any).default as string;

    // Find the createBook function
    const createBookMatch = source.match(
      /export async function createBook[\s\S]*?^}/m
    );
    expect(createBookMatch).not.toBeNull();

    const createBookSource = createBookMatch![0];

    // Verify it has Authorization header
    const hasAuth = createBookSource.includes('Authorization');
    expect(hasAuth, 'BUG-009 CONFIRMED: createBook() does not include Authorization header. ' +
      'All protected endpoints must send the JWT token.').toBe(true);
  });
});

describe('BUG-010: handlePrev always resets to page 1', () => {
  it('should decrement page by 1, not hardcode to 1', async () => {
    const pageModule = await import('./pages/BooksPage?raw');
    const source = (pageModule as any).default as string;

    // Find handlePrev function
    const prevMatch = source.match(/handlePrev[\s\S]*?};/);
    expect(prevMatch).not.toBeNull();

    const prevSource = prevMatch![0];

    // Check if it hardcodes prev = 1
    const hardcodesToOne = prevSource.includes('const prev = 1');
    expect(hardcodesToOne, 'BUG-010 CONFIRMED: handlePrev() hardcodes prev = 1 ' +
      'instead of calculating page - 1.').toBe(false);
  });
});

describe('BUG-011: createPerson() treats 201 as error', () => {
  it('should use res.ok instead of checking for status 200', async () => {
    const apiModule = await import('./api?raw');
    const source = (apiModule as any).default as string;

    // Find createPerson function
    const createPersonMatch = source.match(
      /export async function createPerson[\s\S]*?^}/m
    );
    expect(createPersonMatch).not.toBeNull();

    const createPersonSource = createPersonMatch![0];

    // Check for the buggy status check
    const checksExact200 = createPersonSource.includes('res.status !== 200');
    expect(checksExact200, 'BUG-011 CONFIRMED: createPerson() checks res.status !== 200 ' +
      'instead of !res.ok. The API returns 201 Created, which is treated as an error.').toBe(false);
  });
});

describe('BUG-012: App.tsx passes function reference instead of calling it', () => {
  it('should call isTokenPresent() not pass isTokenPresent as reference', async () => {
    const appModule = await import('./App?raw');
    const source = (appModule as any).default as string;

    // Check for useState(isTokenPresent) without parentheses
    const passesReference = source.includes('useState<boolean>(isTokenPresent)');
    const callsFunction = source.includes('useState<boolean>(isTokenPresent())');

    expect(passesReference && !callsFunction,
      'BUG-012 CONFIRMED: useState(isTokenPresent) passes function reference. ' +
      'Should be useState(isTokenPresent()) to explicitly call the function.'
    ).toBe(false);
  });
});

describe('BUG-016: Logout does not remove token', () => {
  it('should call removeToken() in handleLogout', async () => {
    const appModule = await import('./App?raw');
    const source = (appModule as any).default as string;

    // Find handleLogout
    const logoutMatch = source.match(/handleLogout[\s\S]*?\}, \[/);
    expect(logoutMatch).not.toBeNull();

    const logoutSource = logoutMatch![0];

    const removesToken = logoutSource.includes('removeToken');
    expect(removesToken, 'BUG-016 CONFIRMED: handleLogout does not call removeToken(). ' +
      'The JWT stays in localStorage after logout, and refreshing restores the session.').toBe(true);
  });
});
