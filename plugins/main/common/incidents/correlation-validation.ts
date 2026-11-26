import type { CorrelationPreviewInput } from './contracts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function validateCorrelationPreview(input: CorrelationPreviewInput): void {
  if (!UUID.test(input.policy_id) || !Number.isSafeInteger(input.policy_version) ||
      input.policy_version < 1 || input.policy_version > 2147483647 ||
      !Array.isArray(input.rules) || input.rules.length < 1 || input.rules.length > 100 ||
      new Set(input.rules).size !== input.rules.length || input.rules.some(rule => !UUID.test(rule)) ||
      !Number.isSafeInteger(input.window_minutes) || input.window_minutes < 5 || input.window_minutes > 1440 ||
      !Number.isSafeInteger(input.minimum_findings) || input.minimum_findings < 2 || input.minimum_findings > 100) {
    throw new Error('Invalid policy UUID, version, unique rule UUIDs, window or threshold.');
  }
  const from = Date.parse(input.from), until = Date.parse(input.until), window = input.window_minutes * 60000;
  const utc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.000)?Z$/;
  if (!utc.test(input.from) || !utc.test(input.until) || !Number.isFinite(from) || !Number.isFinite(until) ||
      from < Date.UTC(2000, 0, 1) || until > Date.UTC(2100, 0, 1) ||
      until <= from || until - from > 7 * 86400000 || from % window !== 0 || until % window !== 0) {
    throw new Error('Use UTC timestamps aligned to full policy windows, covering no more than seven days.');
  }
}
