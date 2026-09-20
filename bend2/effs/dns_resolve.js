// DNS
// ===

// A numeric host is the shared io_addr rule. A name is getaddrinfo through
// bun:ffi (Bun has no dns.lookupSync, and an async lookup cannot run while
// the kit is inside libc poll). The C lane uses the same call on a helper
// thread via io_work.
function dns_resolve(host) {
  if (host.length === 0 || host.includes("\0")) {
    return io_fail(22);
  }
  if (io_addr(host, 0) !== null) {
    return io_done(host);
  }
  // Digits and dots only: refuse before lookup (parity with C).
  if (/^[0-9.]+$/.test(host)) {
    return io_fail(22);
  }
  try {
    return io_done(dns_getaddrinfo_v4(host));
  } catch (e) {
    const code = typeof e === "number" ? e : 22;
    return io_fail(code >>> 0);
  }
}

function dns_getaddrinfo_v4(host) {
  const ffi = require("bun:ffi");
  const mac = process.platform === "darwin";
  const lib = ffi.dlopen(mac ? "libSystem.dylib" : "libc.so.6", {
    getaddrinfo: { args: ["cstring", "ptr", "ptr", "ptr"], returns: "i32" },
    freeaddrinfo: { args: ["ptr"], returns: "void" },
    inet_ntop: { args: ["i32", "ptr", "ptr", "u32"], returns: "cstring" },
  });
  // struct addrinfo: Linux puts ai_addr before ai_canonname; Darwin the reverse.
  const hints = new Uint8Array(48);
  const hv = new DataView(hints.buffer);
  hv.setInt32(4, 2, true); // ai_family = AF_INET
  hv.setInt32(8, 1, true); // ai_socktype = SOCK_STREAM
  const out = new BigUint64Array(1);
  const rc = lib.symbols.getaddrinfo(host, null, ffi.ptr(hints), ffi.ptr(out));
  if (rc !== 0) {
    // EAI_NONAME is 8 on Darwin, -2 on glibc; EAI_AGAIN is 2 / -3.
    const code = (mac ? rc === 8 : rc === -2) ? 2
      : (mac ? rc === 2 : rc === -3) ? (mac ? 35 : 11)
      : 22;
    throw code;
  }
  const res = Number(out[0]);
  const ai_addr_off = mac ? 32 : 24;
  const sockaddr = Number(ffi.read.ptr(res + ai_addr_off));
  const sin_addr = sockaddr + 4;
  const buf = new Uint8Array(16);
  const text = lib.symbols.inet_ntop(2, sin_addr, ffi.ptr(buf), 16);
  lib.symbols.freeaddrinfo(res);
  if (!text) {
    throw 22;
  }
  return String(text);
}
