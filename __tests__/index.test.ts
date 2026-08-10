import { scanPromptInjection } from '../lib/scanner';

describe('scanPromptInjection', () => {
  it('should be defined', () => {
    expect(scanPromptInjection).toBeDefined();
  });

  it('should be a function', () => {
    expect(typeof scanPromptInjection).toBe('function');
  });
});
