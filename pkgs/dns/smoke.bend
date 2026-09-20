# Smoke-check the local package before / after hub publish.
import Base
import ./dns.bend as DNS

def show(tag: String, r: Result<&1, &1, (U32 & String), String>) -> IO(Unit):
  match r:
    case Done{ip}:
      IO.print(tag ++ "=" ++ ip)
    case Fail{error}:
      (code, message) = error
      IO.print(tag ++ "=fail:" ++ message)

def main() -> IO(U32):
  do IO<U32>:
    a : Result<&1, &1, (U32 & String), String> <- DNS.resolve("127.0.0.1")
    u : Unit <- show("ipv4", a)
    b : Result<&1, &1, (U32 & String), String> <- DNS.resolve("localhost")
    v : Unit <- show("local", b)
    return 0
