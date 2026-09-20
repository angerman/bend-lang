// DNS
// ===

#include <netdb.h>

// getaddrinfo's EAI_* codes are not errno. Map the ones a program will see
// onto the same codes the rest of the kit uses (ENOENT / EAGAIN / EINVAL).
static u32 dns_eai(int rc) {
  if (rc == EAI_SYSTEM) {
    return errno != 0 ? (u32)errno : EINVAL;
  }
  if (rc == EAI_AGAIN) {
    return EAGAIN;
  }
#if defined(EAI_NONAME)
  if (rc == EAI_NONAME) {
    return ENOENT;
  }
#endif
#if defined(EAI_NODATA)
  if (rc == EAI_NODATA) {
    return ENOENT;
  }
#endif
  return EINVAL;
}

// Digits and dots only: a failed io_sys_addr must not fall through to
// getaddrinfo (macOS accepts leading-zero quads that the kit rejects).
static int dns_numeric_shape(const char* host) {
  if (host[0] == 0) {
    return 0;
  }
  for (const char* p = host; *p != 0; p += 1) {
    if (!((*p >= '0' && *p <= '9') || *p == '.')) {
      return 0;
    }
  }
  return 1;
}

static void resolve_call(IoWork* w) {
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  int rc = getaddrinfo(w->data, NULL, &hints, &res);
  if (rc != 0) {
    w->code = dns_eai(rc);
    return;
  }
  struct sockaddr_in* sin = (struct sockaddr_in*)res->ai_addr;
  if (inet_ntop(AF_INET, &sin->sin_addr, w->text, INET_ADDRSTRLEN) == NULL) {
    w->code = errno != 0 ? (u32)errno : EINVAL;
    freeaddrinfo(res);
    return;
  }
  freeaddrinfo(res);
  w->code = 0;
}

static Term resolve_pack(Env e, IoWork* w) {
  free(w->data);
  if (w->code != 0) {
    free(w->text);
    return io_fail(e, w->code, NULL);
  }
  Term r = io_done(e, io_str(e, w->text, strlen(w->text)));
  free(w->text);
  return r;
}

Term resolve_run(Env e, Term* f, IoWork* w) {
  struct sockaddr_in at;
  struct in_addr soft;
  char out[INET_ADDRSTRLEN];
  w->data = io_cstr(e, f[0], &w->size);
  if (io_nul(w->data, w->size) || w->size == 0) {
    free(w->data);
    return io_fail(e, EINVAL, NULL);
  }
  // Fast path: the same canonical-quad rule TCP.connect / UDP.send_to use.
  if (io_sys_addr(w->data, 0, &at) == 0) {
    if (inet_ntop(AF_INET, &at.sin_addr, out, sizeof out) == NULL) {
      free(w->data);
      return io_fail(e, errno != 0 ? (u32)errno : EINVAL, NULL);
    }
    free(w->data);
    return io_done(e, io_str(e, out, strlen(out)));
  }
  // Hex / short forms (0x7f000001, 127.1): getaddrinfo's inet_aton front
  // end would accept them; TCP.connect refuses. Keep the shape guard too —
  // inet_aton rejects 1.2.3.4.5 / 999.1.1.1 that must stay EINVAL.
  if (inet_aton(w->data, &soft)) {
    free(w->data);
    return io_fail(e, EINVAL, NULL);
  }
  if (dns_numeric_shape(w->data)) {
    free(w->data);
    return io_fail(e, EINVAL, NULL);
  }
  w->text = io_mem(malloc(INET_ADDRSTRLEN));
  return io_work(w, resolve_call, resolve_pack);
}

static void __attribute__((constructor)) resolve_use(void) {
  io_eff(CID_RESOLVE, resolve_run, 0);
}
