import type { AuthResult } from "./types.js";

/**
 * The identity Levitate asserts to a backend that opted into receiving one.
 *
 * Levitate states who authenticated. What that identity may do is the
 * backend's decision, so nothing here is an authorization grant — `scopes` is
 * the gateway's grant, not a permission the backend should defer to.
 *
 * The shape is unversioned and additive-only: new optional fields may appear,
 * existing fields never change meaning or type and are never removed. An
 * incompatible future contract takes a new reserved `_meta` key rather than
 * mutating this one.
 */
export interface Principal {
  issuer: string;
  subject: string;
  subject_type: SubjectType;
  auth_kind: PrincipalAuthKind;
  client_id?: string;
  email?: string;
  scopes: string[];
  asserted_at: string;
}

/**
 * `user` is a person. `owner` is the owner of the deployment rather than any
 * particular human, which is all Levitate's own authorization server can
 * currently identify. A backend that needs per-user authorization must require
 * `user`, and must refuse a value it does not recognize: the set can grow, and
 * an unknown value must never acquire user semantics by default.
 */
export type SubjectType = "user" | "owner";
export type PrincipalAuthKind = "oidc" | "levitate";

export type PrincipalResult =
  | { principal: Principal; refusal?: undefined }
  | { principal?: undefined; refusal: string };

/**
 * Builds the asserted principal from an authentication result.
 *
 * Fields are copied one at a time from an explicit allowlist. `AuthResult` is
 * never spread or reused as the wire object, so access tokens, refresh tokens,
 * authorization codes, PKCE verifiers, the Authorization header and the
 * approval secret have no path into the assertion by construction rather than
 * by filtering. Adding a credential-bearing field to `AuthResult` later cannot
 * leak it here without someone editing this function.
 */
export function buildPrincipal(auth: AuthResult, now: Date = new Date()): PrincipalResult {
  const authKind = principalAuthKind(auth.kind);
  if (!authKind) {
    return { refusal: `auth kind ${auth.kind} identifies no principal` };
  }
  if (!auth.subject) return { refusal: "authentication result carries no subject" };
  if (!auth.issuer) return { refusal: "authentication result carries no issuer" };

  const principal: Principal = {
    issuer: auth.issuer,
    subject: auth.subject,
    subject_type: authKind === "oidc" ? "user" : "owner",
    auth_kind: authKind,
    scopes: [...auth.scopes],
    asserted_at: now.toISOString(),
  };
  // Optional fields are attached only when the authenticator actually resolved
  // one. email is a display attribute; identity is keyed by issuer + subject.
  if (auth.clientId) principal.client_id = auth.clientId;
  if (auth.email) principal.email = auth.email;
  return { principal };
}

/**
 * bearer resolves no person — its subject is the placeholder "bearer-token" —
 * so it is refused here as well as at configuration load. An unrecognized kind
 * is refused for the same reason: inventing an identity is worse than having
 * none, because a backend treats an absent principal as unauthenticated.
 */
function principalAuthKind(kind: AuthResult["kind"]): PrincipalAuthKind | undefined {
  switch (kind) {
    case "oidc":
      return "oidc";
    case "levitate":
      return "levitate";
    case "bearer":
      return undefined;
    default:
      return undefined;
  }
}
