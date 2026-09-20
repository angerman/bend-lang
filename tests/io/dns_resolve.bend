# io (io_dns_resolve): DNS.resolve answers one IPv4 dotted quad. A
# numeric host is the shared canonical-quad rule (Fail EINVAL on a
# leading zero). A name uses getaddrinfo / dns.lookup, so localhost
# comes from the hosts file. no-such-host.invalid must Fail (ENOENT).
import Base

law show_ok:
  for tag : String
  for r   : Result<&1, &1, (U32 & String), String>
  IO(Unit)

def show_ok(tag, r):
  match r:
    case Done{ip}:
      IO.print(tag ++ "=" ++ ip)
    case Fail{error}:
      (code, message) = error
      IO.print(tag ++ "=fail:" ++ message)

law show_fail:
  for tag : String
  for r   : Result<&1, &1, (U32 & String), String>
  IO(Unit)

def show_fail(tag, r):
  match r:
    case Done{ip}:
      IO.print(tag ++ "=unexpected:" ++ ip)
    case Fail{error}:
      (code, message) = error
      IO.print(tag ++ "=fail")

law main:
  IO(U32)

def main():
  do IO<U32>:
    a : Result<&1, &1, (U32 & String), String> <- DNS.resolve("127.0.0.1")
    u : Unit <- show_ok("ipv4", a)
    b : Result<&1, &1, (U32 & String), String> <- DNS.resolve("0127.0.0.1")
    v : Unit <- show_fail("lead", b)
    c : Result<&1, &1, (U32 & String), String> <- DNS.resolve("localhost")
    w : Unit <- show_ok("local", c)
    d : Result<&1, &1, (U32 & String), String> <- DNS.resolve("no-such-host.invalid")
    x : Unit <- show_fail("miss", d)
    return 0

#|ipv4=127.0.0.1
#|lead=fail
#|local=127.0.0.1
#|miss=fail
