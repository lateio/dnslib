% This module implements support for DNS CNAME records (RFC1034, RFC1035)
-module(dnsrr_cname).

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
    valid_data/1,
    normalize_data/1
]).

masterfile_token() -> "cname".
atom() -> cname.
value() -> 5.


masterfile_format() -> dnsrr_domain_common:masterfile_format().
from_masterfile(Data) -> dnsrr_domain_common:from_masterfile(Data).
to_masterfile(Data) -> dnsrr_domain_common:to_masterfile(Data).
to_binary(Data) -> dnsrr_domain_common:to_binary(Data).
from_binary(Data) -> dnsrr_domain_common:from_binary(Data).
valid_data(Data) -> dnsrr_domain_common:valid_data(Data).
normalize_data(Data) -> dnsrr_domain_common:normalize_data(Data).
