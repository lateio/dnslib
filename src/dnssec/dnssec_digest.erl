-module(dnssec_digest).
-export([
    from_to/3
]).

from_to("sha-1", masterfile_token, value) -> 1;
from_to(Value0, masterfile_token, value) ->
    try list_to_integer(Value0) of
        Value when Value < 16#FF -> Value;
        _ -> Value0
    catch
        error:badarg -> Value0
    end.
