# io (io_dns_resolve): DNS.resolve answers one IPv4 dotted quad. A
# numeric host is the shared canonical-quad rule (Fail EINVAL on a
# leading zero or a hex/short form). A name uses getaddrinfo on both
# lanes, so localhost comes from the hosts file. no-such-host.invalid
# must Fail (ENOENT when the resolver answers; leave that coarse).
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

law show_einval:
  for tag : String
  for r   : Result<&1, &1, (U32 & String), String>
  IO(Unit)

def show_einval(tag, r):
  match r:
    case Done{ip}:
      IO.print(tag ++ "=unexpected:" ++ ip)
    case Fail{error}:
      (code, message) = error
      IO.print(tag ++ "=" ++ U32.show(code))

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
    v : Unit <- show_einval("lead", b)
    h : Result<&1, &1, (U32 & String), String> <- DNS.resolve("0x7f000001")
    y : Unit <- show_einval("hex", h)
    c : Result<&1, &1, (U32 & String), String> <- DNS.resolve("localhost")
    w : Unit <- show_ok("local", c)
    d : Result<&1, &1, (U32 & String), String> <- DNS.resolve("no-such-host.invalid")
    x : Unit <- show_fail("miss", d)
    return 0

#|ipv4=127.0.0.1
#|lead=22
#|hex=22
#|local=127.0.0.1
#|miss=fail
