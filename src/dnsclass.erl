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

-export([builtin/0,from_to/3]).

-ifdef(EUNIT).
-include_lib("eunit/include/eunit.hrl").
-endif.

-include("include/pre_otp20_string_macro.hrl").

-callback atom() -> atom().
-callback value() -> 0..16#FFFF.
-callback masterfile_token() -> string().

-optional_callbacks([masterfile_token/0]).

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


-ifdef(EUNIT).
builtin_modules_sanity_test() ->
    Builtin = builtin(),
    CheckFn = fun (FunMod) ->
        FunAtom = FunMod:atom(),
        FunValue = FunMod:value(),
        not (
            from_to(FunAtom, atom, value) =:= FunValue andalso
            from_to(FunValue, value, atom) =:= FunAtom
        )
    end,
    [] = lists:filter(CheckFn, Builtin).
-endif.


-spec from_to(
    Value :: atom() | 0..16#FFFF | string(),
    From :: 'value' | 'module' | 'atom' | 'masterfile_token',
    To   :: 'value' | 'module' | 'atom' | 'masterfile_token' | 'masterfile_token_generic'
) -> atom() | 0..16#FFFF | string().
from_to(Value, value, module) ->
    maps:get(Value, dnsclass_classes:value(), Value);
from_to(Value, value, masterfile_token) when Value >= 0, Value =< 16#FFFF ->
    case maps:get(Value, dnsclass_classes:value(), Value) of
        Value -> from_to(Value, value, masterfile_token_generic);
        Module -> Module:masterfile_token()
    end;
from_to(Value, value, masterfile_token_generic) when Value >= 0, Value =< 16#FFFF ->
    "class" ++ integer_to_list(Value);
from_to(Value, atom, module) ->
    maps:get(Value, dnsclass_classes:atom(), Value);
from_to(Value0, masterfile_token, To) ->
    case string:(?LOWER)(Value0) of
        [$c, $l, $a, $s, $s|Int] ->
            try list_to_integer(Int) of
                Value when To =:= value, Value >= 0, Value =< 16#FFFF -> Value;
                Value when Value >= 0, Value =< 16#FFFF ->
                    case from_to(Value, value, To) of
                        Value -> Value0;
                        ToValue -> ToValue
                    end;
                _ -> Value0
            catch
                error:badarg -> Value0
            end;
        Value ->
            case maps:get(Value, dnsclass_classes:masterfile_token(), Value0) of
                Value0 -> Value0;
                Module when To =:= module -> Module;
                Module -> from_to(Module, module, To)
            end
    end;
from_to(Module, module, value) ->
    Module:value();
from_to(Module, module, atom) ->
    Module:atom();
from_to(Module, module, masterfile_token) ->
    Module:masterfile_token();
from_to(Module, module, masterfile_token_generic) ->
    from_to(Module:value(), value, masterfile_token_generic);
from_to(Value, From, To) when From =/= To ->
    % If either From or To are not allowed, function_clause exception will result
    case from_to(Value, From, module) of
        Value -> Value;
        Module -> from_to(Module, module, To)
    end.
