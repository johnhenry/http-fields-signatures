/**
 * RFC 9421 signature base construction (§2).
 *
 * A "message" is a plain, runtime-agnostic object:
 *   Request:  { method, url, headers }
 *   Response: { status, headers, request? }   // request enables ;req params
 *
 * `headers` may be a plain object (values: string or string[]), an iterable
 * of [name, value] entries, or a Fetch-style Headers instance.
 */

"use strict";

import { parse, serialize } from "http-fields";

// --- header access ---------------------------------------------------------

const headerEntries = (headers) => {
  if (!headers) return [];
  if (typeof headers.entries === "function" && typeof headers.get === "function") {
    return [...headers.entries()];
  }
  if (Array.isArray(headers)) return headers;
  return Object.entries(headers);
};

/** All values for a header name (case-insensitive), in order. */
export const getHeaderValues = (headers, name) => {
  const lower = name.toLowerCase();
  const values = [];
  for (const [key, value] of headerEntries(headers)) {
    if (String(key).toLowerCase() === lower) {
      if (Array.isArray(value)) values.push(...value.map(String));
      else values.push(String(value));
    }
  }
  return values;
};

// --- component identifiers -------------------------------------------------

/**
 * Normalize a covered-component spec to {id, params}. Accepts a bare string
 * ("@method", "content-type") or {id, params} for parameterized components
 * ({id: "@query-param", params: {name: "Pet"}}).
 */
export const normalizeComponent = (component) => {
  if (typeof component === "string") return { id: component, params: {} };
  if (component && typeof component.id === "string") {
    return { id: component.id, params: { ...(component.params || {}) } };
  }
  throw new Error("Component must be a string or {id, params} object");
};

/** Serialize a component identifier as an SFV string item with parameters. */
export const serializeComponentIdentifier = ({ id, params }) => {
  return serialize({ value: id.toLowerCase(), parameters: params }, "item");
};

// --- derived component values (§2.2) ---------------------------------------

const strictEncode = (s) =>
  encodeURIComponent(s).replace(
    /[!'()*]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase()
  );

const requireUrl = (message) => {
  if (!message || typeof message.url !== "string") {
    throw new Error("Message must have an absolute 'url' for this component");
  }
  return new URL(message.url);
};

const deriveValues = (id, params, message) => {
  const url = () => requireUrl(message);
  switch (id) {
    case "@method": {
      if (typeof message.method !== "string") {
        throw new Error("Message must have a 'method'");
      }
      return [message.method.toUpperCase()];
    }
    case "@target-uri":
      return [url().href];
    case "@authority": {
      const u = url();
      return [u.host.toLowerCase()];
    }
    case "@scheme":
      return [url().protocol.replace(/:$/, "").toLowerCase()];
    case "@request-target": {
      const u = url();
      return [u.pathname + u.search];
    }
    case "@path":
      return [url().pathname];
    case "@query": {
      const u = url();
      return [u.search === "" ? "?" : u.search];
    }
    case "@query-param": {
      if (typeof params.name !== "string") {
        throw new Error('@query-param requires a "name" parameter');
      }
      const u = url();
      const lines = [];
      for (const [k, v] of new URLSearchParams(u.search)) {
        if (strictEncode(k) === params.name) lines.push(strictEncode(v));
      }
      if (lines.length === 0) {
        throw new Error(`Query parameter "${params.name}" not found`);
      }
      return lines;
    }
    case "@status": {
      if (!Number.isInteger(message.status)) {
        throw new Error("Message must have an integer 'status'");
      }
      return [String(message.status)];
    }
    default:
      throw new Error(`Unknown derived component: ${id}`);
  }
};

// --- field component values (§2.1) -----------------------------------------

const b64FromBytes = (bytes) => {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin);
};

const fieldValue = (id, params, message, options) => {
  const values = getHeaderValues(message.headers, id).map((v) =>
    v.trim().replace(/[ \t]*\r?\n[ \t]*/g, " ")
  );
  if (values.length === 0) {
    throw new Error(`Header field "${id}" not present in message`);
  }

  if (params.bs === true) {
    const encoder = new TextEncoder();
    return values.map((v) => `:${b64FromBytes(encoder.encode(v))}:`).join(", ");
  }

  if (params.key !== undefined) {
    if (typeof params.key !== "string") {
      throw new Error('"key" parameter must be a string');
    }
    const dict = parse(values.join(", "), "dictionary");
    const member = dict[params.key];
    if (member === undefined) {
      throw new Error(`Dictionary key "${params.key}" not found in "${id}"`);
    }
    if (Array.isArray(member.value)) {
      return serialize([member], "list");
    }
    return serialize({ value: member.value, parameters: member.parameters }, "item");
  }

  if (params.sf === true) {
    const type = options?.fieldTypes?.[id];
    if (!type) {
      throw new Error(
        `"sf" parameter requires the field type of "${id}" via options.fieldTypes`
      );
    }
    return serialize(parse(values.join(", "), type), type);
  }

  if (params.tr === true) {
    throw new Error("Trailer components (;tr) are not supported");
  }

  return values.join(", ");
};

// --- signature base (§2.5) -------------------------------------------------

/**
 * Build the RFC 9421 signature base.
 *
 * @param {object} message - request or response message (see module docs)
 * @param {Array<string|{id: string, params?: object}>} components
 * @param {object} signatureParams - created/expires/nonce/alg/keyid/tag, in
 *   the order they should appear on the wire
 * @param {{fieldTypes?: Record<string, "list"|"dictionary"|"item">}} [options]
 * @returns {{base: string, signatureParamsValue: string}} the base string and
 *   the serialized inner list used in both the base and Signature-Input
 */
export const createSignatureBase = (message, components, signatureParams, options) => {
  const normalized = components.map(normalizeComponent);
  const lines = [];
  const seen = new Set();

  for (const component of normalized) {
    const { params } = component;
    const id = component.id.toLowerCase();

    let target = message;
    if (params.req === true) {
      if (!message.request) {
        throw new Error('";req" component requires message.request');
      }
      target = message.request;
    }

    const identifier = serializeComponentIdentifier({ id, params });
    if (seen.has(identifier)) {
      throw new Error(`Duplicate covered component: ${identifier}`);
    }
    seen.add(identifier);

    const values = id.startsWith("@")
      ? deriveValues(id, params, target)
      : [fieldValue(id, params, target, options)];

    for (const value of values) {
      lines.push(`${identifier}: ${value}`);
    }
  }

  const innerList = normalized.map(({ id, params }) => ({
    value: id.toLowerCase(),
    parameters: params,
  }));
  const signatureParamsValue = serialize(
    [{ value: innerList, parameters: signatureParams || {} }],
    "list"
  );
  lines.push(`"@signature-params": ${signatureParamsValue}`);

  return { base: lines.join("\n"), signatureParamsValue };
};
