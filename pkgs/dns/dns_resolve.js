// DNS
// ===

// A numeric host is the shared io_addr rule. A name is getaddrinfo through
// bun:ffi (Bun has no dns.lookupSync, and an async lookup cannot run while
// the kit is inside libc poll). The C lane uses the same call on a helper
// thread via io_work. This lane blocks for the whole lookup.
function resolve(host) {
  if (host.length === 0 || host.includes("\0")) {
    return io_fail(22);
  }
  if (io_addr(host, 0) !== null) {
    return io_done(host);
  }
  // Hex / short forms: inet_aton accepts what io_addr refuses.
  if (dns_inet_aton(host)) {
    return io_fail(22);
  }
  // Digits and dots only: refuse before lookup (parity with C).
  if (/^[0-9.]+$/.test(host)) {
    return io_fail(22);
  }
  try {
    return io_done(dns_getaddrinfo_v4(host));
  } catch (e) {
    if (typeof e !== "number") {
      throw e;
    }
    return io_fail(e >>> 0);
  }
}

function dns_lib() {
  if (globalThis.BEND_DNS === undefined) {
    const ffi = require("bun:ffi");
    const mac = process.platform === "darwin";
    const lib = ffi.dlopen(mac ? "libSystem.dylib" : "libc.so.6", {
      getaddrinfo: { args: ["ptr", "ptr", "ptr", "ptr"], returns: "i32" },
      freeaddrinfo: { args: ["ptr"], returns: "void" },
      inet_ntop: { args: ["i32", "ptr", "ptr", "u32"], returns: "cstring" },
      inet_aton: { args: ["ptr", "ptr"], returns: "i32" },
    });
    globalThis.BEND_DNS = { ...lib.symbols, ptr: ffi.ptr, read: ffi.read, mac };
  }
  return globalThis.BEND_DNS;
}

function dns_cstr(s) {
  return dns_lib().ptr(new TextEncoder().encode(s + "\0"));
}

function dns_inet_aton(host) {
  const lib = dns_lib();
  const out = new Uint8Array(4);
  return lib.inet_aton(dns_cstr(host), lib.ptr(out)) !== 0;
}

function dns_getaddrinfo_v4(host) {
  const lib = dns_lib();
  const mac = lib.mac;
  // struct addrinfo: Linux puts ai_addr before ai_canonname; Darwin the reverse.
  const hints = new Uint8Array(48);
  const hv = new DataView(hints.buffer);
  hv.setInt32(4, 2, true); // ai_family = AF_INET
  hv.setInt32(8, 1, true); // ai_socktype = SOCK_STREAM
  const out = new BigUint64Array(1);
  const rc = lib.getaddrinfo(dns_cstr(host), null, lib.ptr(hints), lib.ptr(out));
  if (rc !== 0) {
    // EAI_NONAME is 8 on Darwin, -2 on glibc; EAI_AGAIN is 2 / -3.
    const code = (mac ? rc === 8 : rc === -2) ? 2
      : (mac ? rc === 2 : rc === -3) ? (mac ? 35 : 11)
      : 22;
    throw code;
  }
  const res = Number(out[0]);
  try {
    const ai_addr_off = mac ? 32 : 24;
    const sockaddr = Number(lib.read.ptr(res + ai_addr_off));
    const sin_addr = sockaddr + 4;
    const buf = new Uint8Array(16);
    const text = lib.inet_ntop(2, sin_addr, lib.ptr(buf), 16);
    if (!text) {
      throw 22;
    }
    return String(text);
  } finally {
    lib.freeaddrinfo(res);
  }
}
