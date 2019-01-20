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
