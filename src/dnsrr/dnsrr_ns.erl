% This module implements support for DNS NS records (RFC1034, RFC1035)
-module(dnsrr_ns).

-behavior(dnsrr).
-export([
    masterfile_token/0,
    atom/0,
    value/0,
    additionally/1,
    masterfile_format/0,
    from_masterfile/1,
    to_masterfile/1,
    to_binary/1,
    from_binary/1,
    valid_data/1,
    normalize_data/1
]).

masterfile_token() -> "ns".
atom() -> ns.
value() -> 2.


additionally({_, _, in, _, Domain}) ->
    [
        {Domain, a, in},
        {Domain, aaaa, in}
    ];
additionally(_) ->
    [].


masterfile_format() -> dnsrr_domain_common:masterfile_format().
from_masterfile(Data) -> dnsrr_domain_common:from_masterfile(Data).
to_masterfile(Data) -> dnsrr_domain_common:to_masterfile(Data).
to_binary(Data) -> dnsrr_domain_common:to_binary(Data).
from_binary(Data) -> dnsrr_domain_common:from_binary(Data).
valid_data(Data) -> dnsrr_domain_common:valid_data(Data).
normalize_data(Data) -> dnsrr_domain_common:normalize_data(Data).
