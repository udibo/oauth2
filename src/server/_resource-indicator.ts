/** Single-resource syntax for opted-in machine issuance. @module */
import { InvalidTargetError } from "../errors.ts";

const PATH = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[A-Fa-f0-9]{2})*$/;
const QUERY = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[A-Fa-f0-9]{2})*$/;
const USER_INFO = /^(?:[A-Za-z0-9._~!$&'()*+,;=:-]|%[A-Fa-f0-9]{2})*$/;
const REG_NAME = /^(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[A-Fa-f0-9]{2})*$/;
const IP_FUTURE = /^v[0-9a-f]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+$/i;

function validAuthority(authority: string): boolean {
  const at = authority.indexOf("@");
  if (at !== authority.lastIndexOf("@")) return false;
  if (at !== -1 && !USER_INFO.test(authority.slice(0, at))) return false;
  const hostPort = authority.slice(at + 1);
  if (hostPort.startsWith("[")) {
    const end = hostPort.indexOf("]");
    if (end === -1 || !/^(?::[0-9]*)?$/.test(hostPort.slice(end + 1)))
      return false;
    const literal = hostPort.slice(1, end);
    if (IP_FUTURE.test(literal)) return true;
    try {
      // Native parsing validates an IPv6 literal; no lookup or request occurs.
      return new URL(`http://[${literal}]`).hostname.startsWith("[");
    } catch {
      return false;
    }
  }
  const colon = hostPort.lastIndexOf(":");
  return colon === -1
    ? REG_NAME.test(hostPort)
    : REG_NAME.test(hostPort.slice(0, colon)) &&
        /^[0-9]*$/.test(hostPort.slice(colon + 1));
}

function absoluteUri(value: string): boolean {
  const uri = /^[A-Za-z][A-Za-z0-9+.-]*:([^?#]*)(?:\?([^#]*))?$/.exec(value);
  if (!uri || (uri[2] !== undefined && !QUERY.test(uri[2]))) return false;
  let path = uri[1];
  if (path.startsWith("//")) {
    const slash = path.indexOf("/", 2);
    const authority = slash === -1 ? path.slice(2) : path.slice(2, slash);
    if (!validAuthority(authority)) return false;
    path = slash === -1 ? "" : path.slice(slash);
  }
  return PATH.test(path);
}

/**
 * Read zero or one absolute resource URI without a fragment, preserving its
 * exact spelling. Multiple values, including equal repeats, are refused.
 * Call only after opting into the single-resource policy.
 * @throws {InvalidTargetError} For an empty, repeated, non-string or malformed value.
 */
export function resourceIndicatorOf(body: FormData): string | undefined {
  const values = body.getAll("resource");
  if (values.length === 0) return undefined;
  const resource = values[0];
  if (
    values.length !== 1 ||
    typeof resource !== "string" ||
    !absoluteUri(resource)
  ) {
    throw new InvalidTargetError("invalid resource");
  }
  return resource;
}
