# DNS: one IPv4 dotted quad via getaddrinfo. A numeric host is Base's
# shared canonical-quad rule (no leading zeros). A name looks up through
# getaddrinfo on both lanes (JS via bun:ffi, blocking; C on a helper
# thread), so /etc/hosts and search domains apply. TCP.connect stays
# numeric — compose with IO.try.
#
# Hub: 0xf45a7ca0255c5a863fba26e24971a8e0
#   import 0xf45a7ca0255c5a863fba26e24971a8e0/dns.bend as DNS
#   ip : String <- IO.try(String, DNS.resolve("example.com"))
import Base

def resolve(host: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./dns_resolve.c"
  import "./dns_resolve.js"
