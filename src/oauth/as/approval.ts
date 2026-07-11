import { timingSafeEqual } from "node:crypto";
import type { LevitateConfig } from "../../config.js";

export interface PendingAuthorization {
  id: string;
  clientId: string;
  clientName?: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  codeChallenge: string;
  state?: string;
  expiresAt: number;
}

export class PendingAuthorizationStore {
  private readonly entries = new Map<string, PendingAuthorization>();

  create(entry: PendingAuthorization): void {
    this.pruneExpired();
    this.entries.set(entry.id, entry);
  }

  get(id: string): PendingAuthorization | undefined {
    this.pruneExpired();
    const entry = this.entries.get(id);
    if (!entry || entry.expiresAt <= Date.now()) return undefined;
    return entry;
  }

  consume(id: string): PendingAuthorization | undefined {
    const entry = this.get(id);
    if (entry) this.entries.delete(id);
    return entry;
  }

  pruneExpired(now = Date.now()): number {
    let removed = 0;
    for (const [id, entry] of this.entries) {
      if (entry.expiresAt <= now) {
        this.entries.delete(id);
        removed += 1;
      }
    }
    return removed;
  }
}

export function getApprovalSecret(config: LevitateConfig): string | undefined {
  const envName = config.oauth.as.approval_secret_env;
  if (config.oauth.as.approval !== "manual") return undefined;
  if (!envName)
    throw new Error(
      "oauth.as.approval_secret_env is required when oauth.as.approval is manual",
    );
  const secret = process.env[envName];
  if (!secret) throw new Error(`missing oauth approval secret env ${envName}`);
  return secret;
}

export function isApprovalSecretValid(
  value: string | undefined,
  expected: string,
): boolean {
  if (!value) return false;
  const actual = Buffer.from(value);
  const configured = Buffer.from(expected);
  if (actual.length !== configured.length) return false;
  return timingSafeEqual(actual, configured);
}

export function renderApprovalPage(
  pending: PendingAuthorization,
  error?: string,
): string {
  const redirect = new URL(pending.redirectUri);
  const scopes = pending.scopes
    .map((scope) => `<li>${escapeHtml(scope)}</li>`)
    .join("");
  const errorBlock = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Approve Levitate access</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f6f7f9;
      color: #18202a;
    }
    * { box-sizing: border-box; }
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      padding: 32px 16px;
      background:
        radial-gradient(circle at 20% 0%, rgba(44, 110, 203, 0.10), transparent 32%),
        linear-gradient(180deg, #ffffff 0%, #eef2f7 100%);
    }
    main {
      width: min(680px, 100%);
      border: 1px solid #d8dee8;
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.94);
      box-shadow: 0 22px 70px rgba(31, 45, 61, 0.14);
      overflow: hidden;
    }
    header {
      display: flex;
      gap: 18px;
      align-items: center;
      padding: 28px 32px 22px;
      border-bottom: 1px solid #e6ebf2;
      background: linear-gradient(135deg, #ffffff 0%, #f3f7fb 100%);
    }
    img {
      width: 64px;
      height: 64px;
      border-radius: 16px;
      box-shadow: 0 10px 26px rgba(20, 53, 96, 0.16);
    }
    h1 {
      margin: 0;
      font-size: 24px;
      line-height: 1.15;
      letter-spacing: 0;
    }
    .subtitle {
      margin: 6px 0 0;
      color: #617083;
      font-size: 14px;
    }
    section { padding: 24px 32px 30px; }
    dl {
      display: grid;
      grid-template-columns: 150px 1fr;
      gap: 14px 18px;
      margin: 0 0 24px;
      padding: 0;
    }
    dt {
      color: #617083;
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
    }
    dd {
      margin: 0;
      min-width: 0;
      color: #202a36;
      word-break: break-word;
    }
    ul {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      list-style: none;
      padding: 0;
      margin: 0;
    }
    li {
      border: 1px solid #ccd6e2;
      border-radius: 999px;
      padding: 4px 10px;
      background: #f8fafc;
      font-size: 13px;
      font-weight: 650;
    }
    label {
      display: block;
      margin-bottom: 8px;
      color: #354255;
      font-size: 13px;
      font-weight: 700;
    }
    input {
      width: 100%;
      height: 44px;
      border: 1px solid #bdc8d6;
      border-radius: 10px;
      padding: 0 12px;
      font: inherit;
      background: #ffffff;
    }
    input:focus {
      outline: 3px solid rgba(44, 110, 203, 0.18);
      border-color: #2c6ecb;
    }
    .error {
      margin: 0 0 14px;
      border: 1px solid #f1b9b9;
      border-radius: 10px;
      padding: 10px 12px;
      background: #fff4f4;
      color: #9a2d2d;
      font-size: 14px;
      font-weight: 650;
    }
    .actions {
      display: flex;
      gap: 12px;
      justify-content: flex-end;
      margin-top: 18px;
    }
    button {
      min-width: 110px;
      height: 42px;
      border: 1px solid #b9c4d2;
      border-radius: 10px;
      padding: 0 18px;
      font: inherit;
      font-weight: 750;
      cursor: pointer;
      background: #ffffff;
      color: #243142;
    }
    button[value="approve"] {
      border-color: #1f66c1;
      background: #1f66c1;
      color: #ffffff;
    }
    .secret-field {
      position: relative;
    }
    .secret-field input[type="password"],
    .secret-field input[type="text"] {
      width: 100%;
      padding-right: 46px;
    }
    .secret-toggle {
      position: absolute;
      top: 50%;
      right: 12px;
      width: 32px;
      min-width: 32px;
      height: 32px;
      padding: 0;
      transform: translateY(-50%);
      border: 0;
      background: transparent;
      color: #a6b0be;
      cursor: pointer;
    }
    .secret-toggle:hover,
    .secret-toggle:focus {
      color: #637083;
      outline: none;
    }
    .secret-toggle svg { width: 20px; height: 20px; }
    @media (max-width: 560px) {
      header { padding: 22px; }
      section { padding: 22px; }
      dl { grid-template-columns: 1fr; gap: 6px; }
      .actions { flex-direction: column-reverse; }
      button { width: 100%; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <img src="/oauth/assets/levitate-icon.png" alt="" aria-hidden="true">
      <div>
        <h1>Approve Levitate access</h1>
        <p class="subtitle">Confirm this OAuth client before Levitate issues an authorization code.</p>
      </div>
    </header>
    <section>
      <dl>
        <dt>Client</dt>
        <dd>${escapeHtml(pending.clientName ?? pending.clientId)}</dd>
        <dt>Redirect origin</dt>
        <dd>${escapeHtml(redirect.origin)}</dd>
        <dt>Resource</dt>
        <dd>${escapeHtml(pending.resource)}</dd>
        <dt>Scopes</dt>
        <dd><ul>${scopes}</ul></dd>
        <dt>Registration</dt>
        <dd>Dynamic Client Registration</dd>
      </dl>
      ${errorBlock}
      <form method="post" action="/oauth/approval/${escapeHtml(pending.id)}">
        <label for="approval_secret">Approval secret</label>
        <div class="secret-field">
          <input id="approval_secret" name="approval_secret" type="password" autocomplete="current-password">
          <button type="button" id="toggle_secret" class="secret-toggle" aria-label="Reveal approval secret" aria-pressed="false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <g id="eye_open"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></g>
              <g id="eye_closed" hidden><path d="m3 3 18 18"/><path d="M10.6 6.2A11.7 11.7 0 0 1 12 6c6.5 0 10 6 10 6a17 17 0 0 1-2.1 2.8M6.2 6.2C3.5 8 2 12 2 12s3.5 6 10 6a10 10 0 0 0 3.8-.7"/></g>
            </svg>
          </button>
        </div>
        <div class="actions">
          <button type="submit" name="decision" value="deny" formnovalidate>Cancel</button>
          <button type="submit" name="decision" value="approve">Approve</button>
        </div>
      </form>
    </section>
  </main>
  <script>
    const input = document.getElementById("approval_secret");
    const button = document.getElementById("toggle_secret");
    const openIcon = document.getElementById("eye_open");
    const closedIcon = document.getElementById("eye_closed");
    button.addEventListener("click", () => {
      const revealing = input.type === "password";
      input.type = revealing ? "text" : "password";
      button.setAttribute("aria-label", revealing ? "Hide approval secret" : "Reveal approval secret");
      button.setAttribute("aria-pressed", revealing ? "true" : "false");
      openIcon.hidden = revealing;
      closedIcon.hidden = !revealing;
    });
  </script>
</body>
</html>`;
}

export function renderApprovalExpiredPage(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorization request expired</title>
</head>
<body>
  <main>
    <h1>Authorization request expired</h1>
    <p>Start the connection flow again.</p>
  </main>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
