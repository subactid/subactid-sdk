export {
  SubactIdGuard,
  type SubactIdGuardOptions,
  type ToolPolicy,
  type CallEvent,
  type SubactIdAuthExtra,
} from './guard.js';
// The tool-server contract itself lives in `@subactid/server`; these are re-exported so an MCP
// server needs only this package.
export {
  SubactIdAuthError,
  SubactIdToolServer,
  verifyTaskToken,
  JwksCache,
  type DenialReason,
  type RoutePolicy,
  type TaskToken,
  type Actor,
  type VerifyOptions,
  type JwksCacheOptions,
  type AccessEvent,
} from '@subactid/server';
