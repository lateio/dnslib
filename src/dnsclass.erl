% ------------------------------------------------------------------------------
%
% Copyright (c) 2018, Lauri Moisio <l@arv.io>
%
% The MIT License
%
% Permission is hereby granted, free of charge, to any person obtaining a copy
% of this software and associated documentation files (the "Software"), to deal
% in the Software without restriction, including without limitation the rights
% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
% copies of the Software, and to permit persons to whom the Software is
% furnished to do so, subject to the following conditions:
%
% The above copyright notice and this permission notice shall be included in
% all copies or substantial portions of the Software.
%
% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
% THE SOFTWARE.
%
% ------------------------------------------------------------------------------
%
-module(dnsclass).

-callback value() -> 0..16#FFFF.
-callback masterfile_token() -> string().

-export([builtin/0,from_to/3]).

-type class() ::
    'in'   |
    'cs'   |
    'ch'   |
    'hs'   |
    'none' |
    'any'.

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


value_map() ->
    #{
        1   => in,   %% RFC1035
        2   => cs,   %% RFC1035
        3   => ch,   %% RFC1035
        4   => hs,   %% RFC1035
        254 => none,
        255 => any
    }.


atom_map() ->
    #{
        in   => 1,   %% RFC1035
        cs   => 2,   %% RFC1035
        ch   => 3,   %% RFC1035
        hs   => 4,   %% RFC1035
        none => 254,
        any  => 255
    }.


masterfile_token_map() ->
    #{
        "in"  => in,   %% RFC1035
        "cs"  => cs,   %% RFC1035
        "ch"  => ch,   %% RFC1035
        "hs"  => hs    %% RFC1035
    }.


from_to(Value, value, atom) ->
    maps:get(Value, value_map(), Value);
from_to(Value, atom, value) ->
    maps:get(Value, atom_map(), Value);
from_to(Value, masterfile_token, atom) ->
    maps:get(Value, masterfile_token_map(), Value);
from_to(Value, atom, masterfile_token) ->
    case [FileToken || {FileToken, Atom} <- maps:to_list(masterfile_token_map()), Atom =:= Value] of
        [Token] -> Token;
        _ -> Value
    end.
