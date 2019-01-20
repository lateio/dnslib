% ------------------------------------------------------------------------------
%
% Copyright © 2018-2019, Lauri Moisio <l@arv.io>
%
% The ISC License
%
% Permission to use, copy, modify, and/or distribute this software for any
% purpose with or without fee is hereby granted, provided that the above
% copyright notice and this permission notice appear in all copies.
%
% THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES
% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%
% ------------------------------------------------------------------------------
%
-module(dnsclass).

-callback atom() -> atom().
-callback value() -> 0..16#FFFF.
-callback masterfile_token() -> string().

-optional_callbacks([masterfile_token/0]).

-export([builtin/0,from_to/3]).

-type class() :: atom() | 0..16#FFFF.

-export_type([class/0]).

% And do something like what was done with dnsrr and dnsrr_types?
builtin() ->
    [
        dnsclass_in,
        dnsclass_cs,
        dnsclass_ch,
        dnsclass_hs,
        dnsclass_none,
        dnsclass_any
    ].


from_to(Value, value, module) ->
    maps:get(Value, dnsclass_classes:value(), Value);
from_to(Value, atom, module) ->
    maps:get(Value, dnsclass_classes:atom(), Value);
from_to(Value, masterfile_token, module) ->
    maps:get(Value, dnsclass_classes:masterfile_token(), Value);
from_to(Module, module, value) ->
    Module:value();
from_to(Module, module, atom) ->
    Module:atom();
from_to(Module, module, masterfile_token) ->
    Module:masterfile_token();
    % However, with CLASS100 -syntax, every class has a masterfile token, even
    % if it doesn't export one...
from_to(Value, From, To) when From =/= To ->
    % If either From or To are not allowed, function_clause exception will result
    case from_to(Value, From, module) of
        Value -> Value;
        Module -> from_to(Module, module, To)
    end.
