/**
 * Metadata namespace reserved for values Levitate itself authors.
 *
 * Levitate is a stdio-to-HTTP gateway, so a backend's only writer is the
 * Levitate process that spawned it. That process boundary is what lets a
 * backend trust metadata arriving on its stdin without a signature — but only
 * if nothing a remote client sends can appear there wearing Levitate's name.
 * Stripping inbound values under this namespace is what makes that true.
 */
export const LEVITATE_META_PREFIX = "io.github.iomz.levitate/";

/**
 * The key carrying the principal Levitate asserts to a backend that opted in.
 * It sits inside the reserved namespace, so an inbound value under this key is
 * stripped like any other and can never be mistaken for one Levitate authored.
 */
export const PRINCIPAL_META_KEY = `${LEVITATE_META_PREFIX}principal`;

interface RequestParamsWithMeta {
  _meta?: { [key: string]: unknown };
}

/**
 * Removes inbound metadata claiming Levitate's namespace, and returns the
 * reserved keys that were dropped so the caller can log the attempt.
 *
 * Every other `_meta` entry is preserved exactly. When nothing else remains,
 * `_meta` is omitted entirely, so a request that carried only reserved keys
 * reaches the backend indistinguishable from one that carried none.
 *
 * Matching ignores case. Backends read the exact lowercase key, so a
 * case-variant can never be read as a Levitate assertion by a careful backend
 * — but it can by a careless one, and no legitimate key differs from this
 * namespace by case alone.
 */
export function stripReservedMeta<T extends RequestParamsWithMeta>(
  params: T,
): { params: T; strippedKeys: string[] } {
  const meta = params._meta;
  if (!meta) return { params, strippedKeys: [] };

  const strippedKeys: string[] = [];
  const retained: [string, unknown][] = [];
  for (const [key, value] of Object.entries(meta)) {
    if (isReservedMetaKey(key)) {
      strippedKeys.push(key);
      continue;
    }
    retained.push([key, value]);
  }

  if (!strippedKeys.length) return { params, strippedKeys };

  if (!retained.length) {
    const { _meta: _dropped, ...rest } = params;
    return { params: rest as T, strippedKeys };
  }
  // Object.fromEntries defines own data properties. Assigning key by key would
  // instead invoke the inherited setter for a "__proto__" entry, which JSON
  // parsing can produce as an own key: the entry would be dropped rather than
  // forwarded, and the rebuilt object would take the caller's value as its
  // prototype.
  return { params: { ...params, _meta: Object.fromEntries(retained) }, strippedKeys };
}

function isReservedMetaKey(key: string): boolean {
  return key.toLowerCase().startsWith(LEVITATE_META_PREFIX);
}
