-module(dnssec_algorithm).
-export([
    from_to/3
]).

from_to("rsamd5", masterfile_token, value) -> 1;
from_to("dh", masterfile_token, value) -> 2;
from_to("dsa", masterfile_token, value) -> 3;
from_to("ecc", masterfile_token, value) -> 4;
from_to("rsasha1", masterfile_token, value) -> 5;
from_to("indirect", masterfile_token, value) -> 252;
from_to("privatedns", masterfile_token, value) -> 253;
from_to("privateoid", masterfile_token, value) -> 254;
from_to(Value0, masterfile_token, value) ->
    try list_to_integer(Value0) of
        Value when Value < 16#FF -> Value;
        _ -> Value0
    catch
        error:badarg -> Value0
    end.
