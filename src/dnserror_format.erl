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
% This file provides ways to translate errors returned by
% various dnslib functions into user-friendly messages.
-module(dnserror_format).

-export([
    consult_error/1
]).


consult_error({file_error, eacces, Filename}) ->
    io_lib:format("Was not allowed to access file ~s~n", [Filename]);
consult_error({file_error, enoent, Filename}) ->
    io_lib:format("File ~s does not exist~n", [Filename]);
consult_error({file_error, eisdir, Filename}) ->
    io_lib:format("Path ~s points to a directory, not a regular file~n", [Filename]);
consult_error({Type, File, LineNumber, Reason}) ->
    lists:flatten([
        io_lib:format("Line ~B in ~s:~n", [LineNumber, File]),
        consult_error_details(Type, Reason)
    ]).


consult_error_details(syntax_error, {unexpected_quoted, Value}) ->
    io_lib:format("Unexpected quoted string \"~s\"~n"
                  "Quoted strings should only be used in TXT record values and in $INCLUDE directives paths",
                  [Value]);
consult_error_details(syntax_error, {invalid_integer, Value}) ->
    io_lib:format("Invalid integer ~s", [Value]);
consult_error_details(syntax_error, {invalid_ttl, Value}) ->
    io_lib:format("Invalid ttl field ~s"
                  "Following affixes are allowed in ttl fields: m(inute), h(our), d(ay), w(eek)",
                  [Value]);
consult_error_details(syntax_error, at_no_origin) ->
    io_lib:format("Using @ (which translates to current origin) before an $ORIGIN directive is not allowed", []);
consult_error_details(syntax_error, no_previous_domain) ->
    io_lib:format("Domains can only be omitted after at least one has been explicitly stated", []);
consult_error_details(syntax_error, quoted_domain) ->
    io_lib:format("Domains must not be provided as quoted strings", []);
consult_error_details(syntax_error, missing_class) ->
    io_lib:format("Resource record does not have a class", []);
consult_error_details(syntax_error, missing_ttl) ->
    io_lib:format("Resource record does not have a ttl", []);
consult_error_details(syntax_error, class_mismatch) ->
    io_lib:format("Resource record has different class than previous ones. Per RFC1035, Section 5.2, "
                  "all records should have the same class", []);
consult_error_details(syntax_error, relative_no_origin) ->
    io_lib:format("Relative domain names are not allowed without a previous $ORIGIN directive", []);
consult_error_details(syntax_error, linebreak_escape) ->
    io_lib:format("Line ends in a [\\, Linebreak] sequence. For sanity's sake, line break escapes are not allowed. "
                  "If you must include line break in your field, use the quoted form ", []);
consult_error_details(syntax_error, {invalid_escape_integer, Escape}) ->
    io_lib:format("Invalid escape sequence ~s", [Escape]);
consult_error_details(syntax_error, {escape_out_of_range, Escape}) ->
    io_lib:format("Escape sequence ~s out of range (0..255)", [Escape]);

consult_error_details(syntax_error, {too_long_line, LineLen, MaxLen}) ->
    io_lib:format("Line is longer than allowed (length: ~B, allowed: ~B).~n"
                  "If you really need long lines, modify settings (dnsfile:consult/2)~n"
                  "or produce records programmatically (dnsresource:new/2)", [LineLen, MaxLen]);
consult_error_details(syntax_error, Reason) ->
  io_lib:format("Syntax error: ~p", [Reason]);


consult_error_details(resource_record_error, {invalid_token, Token}) ->
    io_lib:format("Invalid token ~s (not a class, ttl or a type)", [Token]);
consult_error_details(resource_record_error, missing_type) ->
    io_lib:format("Resource record does not have a type", []);
consult_error_details(resource_record_error, {out_of_range, ttl, Str, Value}) ->
    io_lib:format("Ttl value ~s (~B) out of range (0..0x7FFFFFFF)", [Str, Value]);

consult_error_details(resource_record_error, {invalid_data, Type, too_few_arguments}) ->
    io_lib:format("Too few arguments for resource record (~p)", [Type]);
consult_error_details(resource_record_error, {invalid_data, Type, too_many_arguments}) ->
    io_lib:format("Too many arguments for resource record (~p)", [Type]);
consult_error_details(resource_record_error, {invalid_data, Type, {unexpected_quoted, Value}}) ->
    io_lib:format("Unexpected quoted value ~s in resource record (~p)", [Value, Type]);
consult_error_details(resource_record_error, {invalid_data, Type, too_long_text_data}) ->
    io_lib:format("Text field too long (over 255 octets) in resource record (~p)", [Type]);
consult_error_details(resource_record_error, {invalid_data, Type, {invalid_integer, Value}}) ->
    io_lib:format("Invalid integer ~s in resource record (~p)", [Value, Type]);

consult_error_details(resource_record_error, {invalid_data, Type, {out_of_range, uint16, Str, Value}}) ->
    io_lib:format("Integer value ~s (~B) out of uint16 range (0..0xFFFF) in resource record (~p)", [Str, Value, Type]);
consult_error_details(resource_record_error, {invalid_data, Type, {out_of_range, uint32, Str, Value}}) ->
    io_lib:format("Integer value ~s (~B) out of uint32 range (0..0xFFFFFFFF) in resource record (~p)", [Str, Value, Type]);
consult_error_details(resource_record_error, {invalid_data, Type, {out_of_range, ttl, Str, Value}}) ->
    io_lib:format("Ttl value ~s (~B) out of range (0..0x7FFFFFFF) in resource record (~p)", [Str, Value, Type]);

consult_error_details(resource_record_error, {invalid_data, Type, {invalid_ttl, Value}}) ->
    io_lib:format("Invalid ttl value ~s in resource record (~p)~n"
                  "Ttl field accept affixes: m(inute), h(our), d(ay), w(eek)", [Value, Type]);

consult_error_details(resource_record_error, {invalid_data, _, {wildcard_domain, Domain}}) ->
    io_lib:format("Wildcard domain (~s) cannot be specified as resource data~n"
                  "If asterisk only labels are required, escape the asterisk character (abc.\\*.d)", [Domain]);
consult_error_details(resource_record_error, {invalid_data, _, relative_no_origin}) ->
    io_lib:format("Relative domain names are not allowed without a previous $ORIGIN directive", []);

consult_error_details(resource_record_error, {invalid_data, _, {invalid_domain, domain_too_long, Domain}}) ->
    case lists:reverse(Domain) of
        [$.|_] -> io_lib:format("Absolute domain too long (over 253 octets)", []);
        _ -> io_lib:format("Domain too long (over 253 octets). "
                           "Take notice that the current $ORIGIN is automatically appended to this relative domain", [])
    end;
consult_error_details(resource_record_error, {invalid_data, _, {invalid_domain, label_too_long, _}}) ->
    io_lib:format("One of the domain labels is too long (over 63 octets)", []);
consult_error_details(resource_record_error, {invalid_data, _, {invalid_domain, empty_label, _}}) ->
    io_lib:format("One of the domain labels is empty (abc..def)", []);
consult_error_details(resource_record_error, {invalid_data, _, {invalid_domain, {escape_out_of_range, Escape}, _}}) ->
    io_lib:format("Escape sequence ~s is out of range (0..255)", [Escape]);
consult_error_details(resource_record_error, {invalid_data, _, {invalid_domain, {invalid_escape_integer, Escape}, _}}) ->
    io_lib:format("Escape sequence ~s is invalid", [Escape]);

consult_error_details(resource_record_error, {invalid_data, Type, invalid_ip_address}) ->
    io_lib:format("Invalid ip address for type ~p", [Type]);
consult_error_details(resource_record_error, {invalid_data, _, at_no_origin}) ->
    io_lib:format("Using @ (which translates to current origin) before an $ORIGIN directive is not allowed", []);
consult_error_details(resource_record_error, {invalid_data, Type, Error}) ->
    io_lib:format("Invalid data for type ~s ~p", [Type, Error]);

consult_error_details(resource_record_error, {type_blacklisted, Type}) ->
    io_lib:format("Type ~p has been blacklisted", [Type]);


consult_error_details(directive_error, relative_origin) ->
    io_lib:format("Relative domains are not allowed in $ORIGIN directive", []);
consult_error_details(directive_error, no_arguments) ->
    io_lib:format("No arguments provided to directive", []);
consult_error_details(directive_error, include_depth) ->
    io_lib:format("Too many recursive $INCLUDE directives", []);
consult_error_details(directive_error, {unexpected_quoted, _}) ->
    io_lib:format("Domain names must not be provided as quoted strings", []);
consult_error_details(directive_error, missing_origin) ->
    io_lib:format("Tried to use relative domain in $INCLUDE without previous $ORIGIN directive", []);
consult_error_details(directive_error, {include_error, Reason}) ->
    lists:flatten([
        io_lib:format("Error while consult()ing $INCLUDED file:~n", []),
        consult_error(Reason)
    ]);
consult_error_details(directive_error, Reason) ->
    io_lib:format("~p", [Reason]);

consult_error_details(_, {invalid_domain, domain_too_long, Domain}) ->
    case lists:reverse(Domain) of
        [$.|_] -> io_lib:format("Absolute domain too long (over 253 octets)", []);
        _ -> io_lib:format("Domain too long (over 253 octets). "
                           "Take notice that the current $ORIGIN is automatically appended to this relative domain", [])
    end;
consult_error_details(_, {invalid_domain, label_too_long, _}) ->
    io_lib:format("One of the domain labels is too long (over 63 octets)", []);
consult_error_details(_, {invalid_domain, empty_label, _}) ->
    io_lib:format("One of the domain labels is empty (abc..def)", []);
consult_error_details(_, {invalid_domain, {escape_out_of_range, Escape}, _}) ->
    io_lib:format("Escape sequence ~s is out of range (0..255)", [Escape]);
consult_error_details(_, {invalid_domain, {invalid_escape_integer, Escape}, _}) ->
    io_lib:format("Escape sequence ~s is invalid", [Escape]).
