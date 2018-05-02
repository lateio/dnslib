% This module implements support for DNS MF records (RFC1034, RFC1035)
-module(dnsrr_mf).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    from_binary/1,
    from_binary_finalize/1
]).

masterfile_token() -> "mf".
atom() -> mf.
value() -> 4.


masterfile_format() -> dnsrr_domain_common:masterfile_format().
from_masterfile(Data) -> dnsrr_domain_common:from_masterfile(Data).
to_masterfile(Data) -> dnsrr_domain_common:to_masterfile(Data).
to_binary(Data) -> dnsrr_domain_common:to_binary(Data).
from_binary(Data) -> dnsrr_domain_common:from_binary(Data).
from_binary_finalize(Data) -> dnsrr_domain_common:from_binary_finalize(Data).
