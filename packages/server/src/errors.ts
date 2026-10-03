/** Why a token or a call was refused. Stable strings, safe to log and to put in an audit trail. */
export type DenialReason =
  | 'missing_token'
  | 'malformed_token'
  | 'unsupported_algorithm'
  | 'unknown_key'
  | 'invalid_signature'
  | 'wrong_type'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'expired'
  | 'not_yet_valid'
  | 'no_subject'
  | 'subject_is_agent'
  | 'no_actor'
  | 'delegation_too_deep'
  | 'unknown_route'
  | 'unknown_tool'
  | 'insufficient_scope'
  | 'not_active'
  | 'introspection_unavailable'
  | 'keys_unavailable';

/**
 * A refusal, with the HTTP status a transport should answer with and the reason a log should
 * carry. The message names the reason, never the token.
 */
export class SubactIdAuthError extends Error {
  readonly status: 401 | 403 | 503;
  readonly reason: DenialReason;
  /**
   * How long to wait before asking again, in whole seconds, when the refusal came from a control
   * plane that named an interval — it rate limits this tool server as it does any other source
   * (spec section 8). A caller told the interval is one that does not spend the next bucket too.
   */
  readonly retryAfterSeconds: number | undefined;

  constructor(
    status: 401 | 403 | 503,
    reason: DenialReason,
    message: string,
    retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'SubactIdAuthError';
    this.status = status;
    this.reason = reason;
    this.retryAfterSeconds = retryAfterSeconds;
  }

  /** The `WWW-Authenticate` value for a 401 or 403, per RFC 6750. */
  wwwAuthenticate(realm: string): string {
    if (this.reason === 'missing_token') {
      return `Bearer realm="${quotable(realm)}"`;
    }
    const error = this.status === 403 ? 'insufficient_scope' : 'invalid_token';
    return `Bearer realm="${quotable(realm)}", error="${error}", error_description="${quotable(this.message)}"`;
  }
}

/**
 * Text as RFC 6750 section 3 allows it inside a quoted-string: printable ASCII without `"` or
 * `\`. Anything else — a control character, a newline, a byte above ASCII — becomes a space.
 *
 * A message can carry text this server did not write: the control plane's `revocation_reason`
 * reaches `error_description` this way. A newline in a header value ends the header and begins
 * another one, and a header value Node refuses outright turns a clean 401 into a dropped
 * connection, so the value is made safe here rather than trusted to be.
 */
function quotable(text: string): string {
  return text.replace(/[^\x20\x21\x23-\x5b\x5d-\x7e]/g, ' ');
}
