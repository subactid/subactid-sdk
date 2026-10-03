/** The control plane's discovery document, the fields this client uses. */
export interface Discovery {
  issuer: string;
  token_endpoint: string;
  /** Not checked to be present; checked to be under the issuer when it is. */
  introspection_endpoint?: string;
  /** Not checked to be present; checked to be under the issuer when it is. `revoke()` refuses without it. */
  revocation_endpoint?: string;
  jwks_uri: string;
}

/** A successful answer from the token endpoint, for an exchange or a refresh. */
export interface TokenResponse {
  access_token: string;
  issued_token_type: string;
  token_type: string;
  expires_in: number;
  scope: string;
  /** The task grant. */
  refresh_token: string;
  task_id: string;
  task_expires_at: string;
}

/** What an exchange asks for. */
export interface ExchangeRequest {
  /** The user's access token from the upstream identity provider. */
  subjectToken: string;
  /** The audience the task is for. */
  resource: string;
  /** Scopes wanted, space-separated. The task gets the intersection with what the user and the agent hold. */
  scope: string;
}
