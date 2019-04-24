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
% This file allows DNS message to be serialized to and parsed from binary
% wire format.
-module(dnswire).

-export([
    from_binary/1,
    to_binary/1,
    to_binary/2,
    binary_to_domain/1,
    domain_to_binary/1,
    domain_binary_length/1,
    to_iolist/1,
    to_iolist/2,
    to_binary_domain/2,
    from_binary_domain/2,
    return_code/1,
    opcode/1,
    finalize_resource_data/2
]).

-include_lib("dnslib/include/dnslib.hrl").

-spec boolean
    (1) -> 'true';
    (0) -> 'false';
    ('true') -> 1;
    ('false') -> 0.
boolean(0)     -> false;
boolean(1)     -> true;
boolean(true)  -> 1;
boolean(false) -> 0.


return_code(0) -> ok;              %% RFC1035
return_code(1) -> format_error;    %% RFC1035
return_code(2) -> server_error;    %% RFC1035
return_code(3) -> name_error;      %% RFC1035
return_code(4) -> not_implemented; %% RFC1035
return_code(5) -> refused;         %% RFC1035

%return_code(6)  -> yxdomain; %% RFC2136
%return_code(7)  -> yxrrset;  %% RFC2136
%return_code(8)  -> nxrrset;  %% RFC2136
%return_code(9)  -> notauth;  %% RFC2136
%return_code(10) -> notzone;  %% RFC2136

return_code(16) -> bad_version; %% RFC6891

return_code(ok)              -> 0; %% RFC1035
return_code(format_error)    -> 1; %% RFC1035
return_code(server_error)    -> 2; %% RFC1035
return_code(name_error)      -> 3; %% RFC1035
return_code(not_implemented) -> 4; %% RFC1035
return_code(refused)         -> 5; %% RFC1035

%return_code(yxdomain) ->  6; %% RFC2136
%return_code(yxrrset)  ->  7; %% RFC2136
%return_code(nxrrset)  ->  8; %% RFC2136
%return_code(notauth)  ->  9; %% RFC2136
%return_code(notzone)  -> 10; %% RFC2136

return_code(bad_version) -> 16;  %% RFC6891

return_code(Value) when is_integer(Value) -> Value.


opcode(0) -> query;   %% RFC1035
opcode(1) -> i_query; %% RFC1035
opcode(2) -> status;  %% RFC1035
%opcode(3) -> unassigned
opcode(4) -> notify;  %% RFC1996
%opcode(5) -> update;  %% RFC2136

opcode(query)   -> 0; %% RFC1035
opcode(i_query) -> 1; %% RFC1035
opcode(status)  -> 2; %% RFC1035
opcode(notify)  -> 4; %% RFC1996
%opcode(update)  -> 5; %% RFC2136
opcode(Value) when is_integer(Value) -> Value.


% Header
-define(HEADER,
<<
	Id:16,
	IsResponse:1, OpCode:4, Authoritative:1, Truncated:1, RecursionDesired:1, RecursionAvailable:1, Reserved:1/bits, AuthData:1, CheckingDisabled:1, ResponseCode:4
>>).

% Matches RDATA portion after name
-define(RDATA, <<
	Type:16,
	Class:16,
	Ttl:32,
	DataLen:16,
	RData:DataLen/binary,
	Rest/binary
>>).

-record(bin_state, {
    offset=12 :: non_neg_integer(),
    max_length=16#FFFF :: 12..16#FFFF,
    normalize_domains=false :: boolean() | 'both', % 'both' = {normalized, Orig, Norm}.
    trie=dnstrie:new() :: dnstrie:trie(),
    refs=[] :: [{{non_neg_integer(),pos_integer()},dnslib:domain()}],
    compress=true :: boolean(),
    compress_rdata=true :: boolean(),
    quit_on_error=true :: boolean(),
    message_bin :: binary() | 'undefined',
    invalid_questions=0 :: non_neg_integer(),
    invalid_resources=0 :: non_neg_integer(),
    edns=true :: boolean(),
    truncate=true :: boolean()
}).


-spec binary_to_domain(Bin :: binary())
    -> {'ok', dnslib:non_wildcard_domain(), Tail :: binary()}
     | {'compressed', dnslib:compressed_domain(), Tail :: binary()}
     %{'extended', Type :: 0..63, binary()},
     | {'error',
         'truncated_domain' |
         'empty_binary'     |
         'domain_too_long'  |
         {'invalid_length', Bit1 :: 0..1, Bit2 :: 0..1}
       }.
%binary_to_domain(<<0:1, 1:1, Type:6, Rest/binary>>) ->
%    {extended, Type, Rest};
binary_to_domain(<<>>) ->
    {error, empty_binary};
binary_to_domain(Bin) when is_binary(Bin) ->
    binary_to_domain(Bin, [], 0);
binary_to_domain(Bits) when is_bitstring(Bits) ->
    {error, truncated_domain}.

binary_to_domain(<<_/binary>>, _, BytesUsed) when BytesUsed >= ?DOMAIN_MAX_OCTETS ->
    {error, domain_too_long};
binary_to_domain(<<0, Tail/binary>>, Acc, _) ->
    {ok, lists:reverse(Acc), Tail};
binary_to_domain(<<1:1, 1:1, Ref:14, Tail/binary>>, Acc, _) ->
    {compressed, {compressed, Ref, Acc}, Tail};
binary_to_domain(<<0:1, 1:1, 1:6, Tail0/binary>>, Acc, BytesUsed) -> % Binary label (RFC2673)
    case Tail0 of
        <<0, Label:256, Tail1/binary>> -> binary_to_domain(Tail1, [{binary, <<Label:256>>}|Acc], BytesUsed + 2 + 32);
        <<Bits, Label:Bits, Tail1/binary>> when Bits rem 8 =:= 0 -> binary_to_domain(Tail1, [{binary, <<Label:Bits>>}|Acc], BytesUsed + 2 + Bits div 8);
        <<Bits, Label:Bits, _Padding:7, Tail1/binary>> when Bits rem 8 =:= 1 -> binary_to_domain(Tail1, [{binary, <<Label:Bits>>}|Acc], BytesUsed + 3 + Bits div 8);
        <<Bits, Label:Bits, _Padding:6, Tail1/binary>> when Bits rem 8 =:= 2 -> binary_to_domain(Tail1, [{binary, <<Label:Bits>>}|Acc], BytesUsed + 3 + Bits div 8);
        <<Bits, Label:Bits, _Padding:5, Tail1/binary>> when Bits rem 8 =:= 3 -> binary_to_domain(Tail1, [{binary, <<Label:Bits>>}|Acc], BytesUsed + 3 + Bits div 8);
        <<Bits, Label:Bits, _Padding:4, Tail1/binary>> when Bits rem 8 =:= 4 -> binary_to_domain(Tail1, [{binary, <<Label:Bits>>}|Acc], BytesUsed + 3 + Bits div 8);
        <<Bits, Label:Bits, _Padding:3, Tail1/binary>> when Bits rem 8 =:= 5 -> binary_to_domain(Tail1, [{binary, <<Label:Bits>>}|Acc], BytesUsed + 3 + Bits div 8);
        <<Bits, Label:Bits, _Padding:2, Tail1/binary>> when Bits rem 8 =:= 6 -> binary_to_domain(Tail1, [{binary, <<Label:Bits>>}|Acc], BytesUsed + 3 + Bits div 8);
        <<Bits, Label:Bits, _Padding:1, Tail1/binary>> when Bits rem 8 =:= 7 -> binary_to_domain(Tail1, [{binary, <<Label:Bits>>}|Acc], BytesUsed + 3 + Bits div 8);
        _ -> {error, truncated_domain}
    end;
binary_to_domain(<<0:1, 1:1, ELT:6, _/binary>>, Acc, BytesUsed) ->
    {error, {unknown_extended_label_type, ELT}};
binary_to_domain(<<0:1, 0:1, Rest/bits>>, Acc, BytesUsed) ->
    case Rest of
        <<Len:6, Label:Len/binary, Tail/binary>> -> binary_to_domain(Tail, [Label|Acc], BytesUsed+1+Len);
        _ -> {error, truncated_domain}
    end;
binary_to_domain(<<B1:1, B2:1, _:6, _/binary>>, _, _) ->
    {error, {invalid_length, B1, B2}};
binary_to_domain(Bin, _, _) ->
    io:format("~p~n", [Bin]),
    {error, truncated_domain}.


-spec domain_to_binary(Domain :: dnslib:non_wildcard_domain() | dnslib:compressed_domain())
    -> {'ok', binary()}
     | {'error',
         'domain_too_long' |
         'label_too_long'  |
         'empty_label'     |
         'ref_out_of_range'
       }.
domain_to_binary({compressed, Ref, _}) when Ref > 16#3FFF; Ref < 0 ->
    {error, ref_out_of_range};
domain_to_binary({compressed, Ref, Domain}) ->
    case domain_to_binary(lists:reverse(Domain), <<>>) of
        {ok, Bin} when byte_size(Bin) < ?DOMAIN_MAX_OCTETS - 1 ->
            StartLen = byte_size(Bin) - 1,
            <<BinStart:StartLen/binary, 0>> = Bin,
            {ok, <<BinStart/binary, 3:2, Ref:14>>};
        {error, _}=Tuple -> Tuple
    end;
domain_to_binary(Domain) ->
    domain_to_binary(Domain, <<>>).

-spec domain_to_binary(dnslib:domain(), binary()) ->
    {'ok', binary()} |
    {'error',
        'domain_too_long' |
        'label_too_long'  |
        'empty_label'
    }.
domain_to_binary(_, Acc) when byte_size(Acc) >= ?DOMAIN_MAX_OCTETS -> %
    {error, domain_too_long};
domain_to_binary([], Acc) ->
    {ok, <<Acc/binary, 0>>};
domain_to_binary([Label|_], _) when byte_size(Label) > 63 ->
    {error, label_too_long};
domain_to_binary([<<>>|_], _) ->
    {error, empty_label};
domain_to_binary([{binary, Label}|Rest], Acc) when is_bitstring(Label), bit_size(Label) > 0 ->
    Bitsize = bit_size(Label),
    if
        Bitsize =:= 256 -> domain_to_binary(Rest, <<Acc/binary, 0:1, 1:1, 1:6, 0, Label/bits>>);
        Bitsize < 256 -> domain_to_binary(Rest, <<Acc/binary, 0:1, 1:1, 1:6, (bit_size(Label)), Label/bits, 0:(8-(bit_size(Label) rem 8))>>)
    end;
domain_to_binary([Label|Rest], Acc) ->
    domain_to_binary(Rest, <<Acc/binary, (byte_size(Label)), Label/binary>>).


-spec domain_binary_length(dnslib:non_wildcard_domain() | dnslib:compressed_domain()) -> pos_integer().
domain_binary_length([]) ->
    1;
domain_binary_length({compressed, _, Domain}) ->
    domain_binary_length(Domain, 0) + 1;
domain_binary_length(Domain) ->
    domain_binary_length(Domain, 0).

domain_binary_length([], Len) ->
    Len + 1;
domain_binary_length([Label|Domain], Len) ->
    domain_binary_length(Domain, Len + 1 + byte_size(Label)).


% There's literally no point adding refs for root domain. It should not be considered when/for compression
% But as it's possible to Ref to a root domain, we'll still keep those refs around...
%add_domain_ref([], _, _, State) ->
%    State;
add_domain_ref(Domain, DomainOffset, DomainBytes, State = #bin_state{refs=Refs}) ->
    % Although DomainBytes =/= dnslib:domain_binary_length(Domain),
    % compression reference has to refer to a byte that's actually physically
    % present in the domain. Thus we can use DomainBytes as the
    % "length" of the domain in Refs
    %
    % Keeping in mind how the offset is encoded, we only have 14 bits to work with.
    % Thus in unusually long messages, we lose the ability to refer to later domains
    % in domain compressions
    if
        DomainOffset =< 16#3FFF -> State#bin_state{refs=[{{DomainOffset,DomainBytes},Domain}|Refs]};
        true -> State
    end.


compress_domain([], _, State = #bin_state{offset=Offset}) ->
    % No reason to compress root domain
    {<<0>>, State#bin_state{offset=Offset+1}};
compress_domain(Domain, AllowCompress, State0 = #bin_state{trie=Trie0,offset=Offset0}) ->
    case dnstrie:get_path(lists:reverse(Domain), Trie0) of
        {full, [Ref|_]} when AllowCompress -> {<<3:2, Ref:14>>, State0#bin_state{offset=Offset0+2}};
        {full, _} ->
            {ok, Bin} = domain_to_binary(Domain),
            {Bin, State0#bin_state{offset=Offset0+byte_size(Bin)}};
        {partial, Match = [Ref|_]} ->
            Diff = length(Domain) - length(Match),
            State1 = #bin_state{offset=Offset1} = populate_compression_trie(Domain, Diff, State0),
            case AllowCompress of
                true ->
                    {NewLabels, _} = lists:split(Diff, Domain),
                    {ok, Bin0} = domain_to_binary(NewLabels),
                    LengthSansZero = byte_size(Bin0) - 1,
                    <<Bin:LengthSansZero/binary, _/binary>> = Bin0,
                    {<<Bin/binary, 3:2, Ref:14>>, State1#bin_state{offset=Offset1+2}};
                false ->
                    {ok, Bin} = domain_to_binary(Domain),
                    {Bin, State1#bin_state{offset=Offset0+byte_size(Bin)}}
            end;
        {none, []} ->
            State1 = #bin_state{offset=Offset1} = populate_compression_trie(Domain, length(Domain), State0),
            {ok, Bin} = domain_to_binary(Domain),
            {Bin, State1#bin_state{offset=Offset1+1}}
    end.


populate_compression_trie(_, 0, State) ->
    State;
populate_compression_trie(Domain = [Label|Next], Limit, State = #bin_state{offset=Offset,trie=Trie}) ->
    populate_compression_trie(Next, Limit-1, State#bin_state{trie=dnstrie:set(lists:reverse(Domain),Offset,Trie),offset=Offset+1+byte_size(Label)}).


compress_datalist([], Acc, State) ->
    RData = lists:reverse(Acc),
    {RData, iolist_size(RData), State};
compress_datalist([{domain, Compress, Domain0}|Rest], Acc, State0 = #bin_state{compress_rdata=CompressData}) ->
    {Domain1, State1} = compress_domain(Domain0, Compress andalso CompressData, State0),
    compress_datalist(Rest, [Domain1|Acc], State1);
compress_datalist([Entry|Rest], Acc, State = #bin_state{offset=Offset}) ->
    compress_datalist(Rest, [Entry|Acc], State#bin_state{offset=Offset+iolist_size(Entry)}).


decompress_domain({compressed, Ref, Acc, _}, State) ->
    decompress_domain({compressed, Ref, Acc}, State);
decompress_domain({compressed, Ref, Acc}=Tuple, #bin_state{refs=Refs,message_bin=Bin,offset=Offset}) ->
    case find_ref(Ref, Refs) of
        undefined ->
            % No ref, use binary of the message to find the domain (as it might
            % refer to a domain invisible to us, ie: in an unknown record)
            case decompress_domain_from_binary(Tuple, Offset, Bin) of
                {ok, _}=RetTuple -> RetTuple;
                {error, _} -> {error, invalid_compression}
            end;
        {Ref, DomainTail} ->
            case dnslib:append_domain(lists:reverse(Acc), DomainTail) of
                {ok, _}=RetTuple -> RetTuple;
                {error, _} -> {error, invalid_compression}
            end;
        {DomainStart, SuperDomain} ->
            case find_ref_in_domain(Ref, DomainStart, SuperDomain) of
                undefined -> {error, error_invalid_compression};
                {Ref, DomainTail} ->
                    case dnslib:append_domain(lists:reverse(Acc), DomainTail) of
                        {ok, _}=RetTuple -> RetTuple;
                        {error, _} -> {error, invalid_compression}
                    end
            end
    end;
decompress_domain(Domain, _) when is_list(Domain) ->
    {ok, Domain}.

decompress_domain_from_binary({compressed, Ref, _}, Offset, _) when Ref >= Offset ->
    {error, forward_reference};
decompress_domain_from_binary({compressed, Ref, Acc}, _, MessageBin) ->
    <<_:Ref/binary, Bin/binary>> = MessageBin,
    case binary_to_domain(Bin) of
        {compressed, {compressed, NewRef, NewAcc}, _} ->
            decompress_domain_from_binary({compressed, NewRef, lists:append(NewAcc, Acc)}, Ref, MessageBin);
        {ok, DomainTail, _} ->
            case dnslib:append_domain(lists:reverse(Acc), DomainTail) of
                {ok, _}=RetTuple -> RetTuple;
                {error, _} -> {error, invalid_compression}
            end;
        _ -> {error, invalid_compression}
    end.


decompress_ref_datalist([], Acc, State) ->
    {ok, lists:reverse(Acc), State};
decompress_ref_datalist([{domain, Domain, DomainOffset}|Rest], Acc, State0 = #bin_state{offset=Offset}) ->
    State1 = add_domain_ref(Domain, Offset+DomainOffset, domain_binary_length(Domain), State0),
    decompress_ref_datalist(Rest, [Domain|Acc], State1);
decompress_ref_datalist([{compressed, _, DomainAcc, DomainOffset}=Tuple|Rest], Acc, State0 = #bin_state{offset=Offset}) ->
    % We need to add ref to this domain...
    case decompress_domain(Tuple, State0) of
        {ok, Domain} ->
            State1 = add_domain_ref(Domain, Offset+DomainOffset, domain_binary_length(DomainAcc), State0),
            decompress_ref_datalist(Rest, [Domain|Acc], State1);
        {error, _}=ErrTuple -> ErrTuple
    end;
decompress_ref_datalist([Data|Rest], Acc, State) ->
    decompress_ref_datalist(Rest, [Data|Acc], State).


find_ref(_, []) ->
    undefined;
find_ref(Ref, [{{Ref, _}, Domain}|_]) ->
    {Ref, Domain};
find_ref(Ref, [{{Start, Length}, Domain}|_]) when Ref > Start, Ref < (Start + Length) ->
    {Start, Domain};
find_ref(Ref, [_|Rest]) ->
    find_ref(Ref, Rest).


find_ref_in_domain(_, _, []) ->
    undefined;
find_ref_in_domain(Ref, Offset, _) when Offset > Ref ->
    undefined;
find_ref_in_domain(Ref, Ref, Domain) ->
    {Ref, Domain};
find_ref_in_domain(Ref, Offset, [Label|Rest]) ->
    find_ref_in_domain(Ref, Offset+byte_size(Label)+1, Rest).


from_binary_questions(<<Data/binary>>, 0, [{Section, Count}|RestCounts], State, Acc) ->
    from_binary_resources(Data, Section, Count, RestCounts, State, Acc);
from_binary_questions(<<>>, _, _, State, Acc) ->
    error({truncated_message, State, Acc});
from_binary_questions(<<Data/binary>>, Count, OtherCounts, State0 = #bin_state{offset=Offset,invalid_questions=Invalid,quit_on_error=Quit}, Acc) ->
    case
        case binary_to_domain(Data) of
            {_, TmpDomain, TmpTail} ->
                case decompress_domain(TmpDomain, State0) of
                    {ok, Decompressed} -> {Decompressed, is_tuple(TmpDomain), domain_binary_length(TmpDomain), TmpTail};
                    {error, _} when Quit -> error({invalid_domain, State0, Acc});
                    {error, _} ->
                        %% Invalid compression, but we can skip the question
                        {error, domain_binary_length(TmpDomain) + 1, TmpTail}
                end;
            {error, truncated_domain} -> error({truncated_domain, State0, Acc});
            {error, Reason} -> error({invalid_domain, Reason, State0, Acc})
        end
    of
        {Domain, WasCompressed, DomainBytes, Tail} ->
            DomainRefBytes = case WasCompressed of
                true -> DomainBytes - 2;
                false -> DomainBytes
            end,
            case Tail of
                <<TypeValue:16, ClassValue:16, Rest/binary>> ->
                    Type = dnsrr:from_to(TypeValue, value, atom), % This will call Module:atom() when the type is known, thus loading the module
                    Class = dnsclass:from_to(ClassValue, value, atom),
                    case
                        {
                            dnsrr:class_valid_for_type(Class, Type),
                            dnsrr:section_valid_for_type(question, Type)
                        }
                    of
                        {true, true} ->
                            State1 = add_domain_ref(Domain, Offset, DomainRefBytes, State0),
                            Entry = {Domain, Type, Class},
                            from_binary_questions(Rest, Count - 1, OtherCounts, State1#bin_state{offset=Offset + DomainBytes + 4}, [Entry|Acc]);
                        {false, _} when Quit -> error({invalid_question_class, Type, Class, State0, Acc});
                        {_, false} when Quit -> error({invalid_section, Type, question, State0, Acc});
                        _ -> from_binary_questions(Rest, Count - 1, OtherCounts, State0#bin_state{offset=Offset + DomainBytes + 4, invalid_questions=Invalid+1}, [invalid|Acc])
                    end;
                _ -> error({truncated_resource_data, State0, Acc})
            end;
        {error, DomainBytes, Tail} ->
            case Tail of
                <<_:16, _:16, Rest/binary>> ->
                    from_binary_questions(Rest, Count - 1, OtherCounts, State0#bin_state{offset=Offset + DomainBytes + 4, invalid_questions=Invalid+1}, [invalid|Acc]);
                _ -> error({truncated_resource_data, State0, Acc})
            end
    end.


finalize_resource_data(DataList, Module) ->
    finalize_entry_data(DataList, erlang:function_exported(Module, from_binary_finalize, 1), Module).

finalize_entry_data([_|_] = DataList, true, Module) ->
    {ok, EntryData} = Module:from_binary_finalize(DataList),
    EntryData;
finalize_entry_data([Data], false, _) ->
    Data;
finalize_entry_data([_|_] = DataList, false, _) ->
    list_to_tuple(DataList).


-define(RMATCH, <<Type0:16, Class0:16, Ttl:32, DataLen:16, RData:DataLen/binary, Rest/binary>>).
from_binary_resource_data(?RMATCH, Section, Count, RestCounts, Domain, DomainBytes, Acc, State0 = #bin_state{offset=Offset0,invalid_resources=Invalid,quit_on_error=Quit}) ->
    Class = dnsclass:from_to(Class0, value, atom),
    case dnsrr:from_to(Type0, value, module) of
        Type0 ->
            Entry = {Domain, Type0, Class, Ttl, RData},
            from_binary_resources(Rest, Section, Count - 1, RestCounts, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen}, [Entry|Acc]);
        Module ->
            Type = Module:atom(), % Good, make sure that the module is loaded
            % Even if we get an opt resource, we can't apply it
            % to the message here...
            % Just handle it when handling the query?
            % Start with additional records
            case
                {
                    dnsrr:class_valid_for_type(Class, Type),
                    dnsrr:section_valid_for_type(Section, Type)
                }
            of
                {true, true} ->
                    try Module:from_binary(RData) of
                        {error, _} when Quit -> error({invalid_resource_data, Type, RData, State0, Acc});
                        {error, _} -> from_binary_resources(Rest, Section, Count - 1, RestCounts, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen,invalid_resources=Invalid+1}, [invalid|Acc]);
                        {ok, EntryData} ->
                            Entry = {Domain, Type, Class, Ttl, EntryData},
                            from_binary_resources(Rest, Section, Count - 1, RestCounts, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen}, [Entry|Acc]);
                        {domains, DecompRefList} ->
                            % It's possible that decompression produces an error. We should be prepared to handle that...
                            case decompress_ref_datalist(DecompRefList, [], State0#bin_state{offset=Offset0+DomainBytes+10}) of
                                {ok, DataList, State1 = #bin_state{offset=Offset1}} ->
                                    EntryData = finalize_resource_data(DataList, Module),
                                    Entry = {Domain, Type, Class, Ttl, EntryData},
                                    from_binary_resources(Rest, Section, Count - 1, RestCounts, State1#bin_state{offset=Offset1 + DataLen}, [Entry|Acc]);
                                _ when Quit -> error({invalid_resource_data, Type, RData, State0, Acc});
                                _ ->
                                    from_binary_resources(Rest, Section, Count - 1, RestCounts, State0#bin_state{offset=Offset0 + DataLen, invalid_resources=Invalid+1}, [invalid|Acc])
                                    % Continue. Although the resource is invalid, we can handle rest of the message
                            end
                    catch
                        error:function_clause -> error({invalid_resource_data, Type, RData, State0, Acc})
                    end;
                {false, _} when Quit -> error({invalid_resource_class, Type, Class, State0, Acc});
                {_, false} when Quit -> error({invalid_section, Type, Section, State0, Acc});
                _ -> from_binary_resources(Rest, Section, Count - 1, RestCounts, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen,invalid_resources=Invalid+1}, [invalid|Acc])
            end
    end;
from_binary_resource_data(_, _, _, _, _, _, Acc, State0) ->
    error({truncated_resource_data, State0, Acc}).


from_binary_resources(<<Tail/binary>>, _, 0, [], State, Acc) ->
    {ok, Tail, State, Acc};
from_binary_resources(<<Tail/binary>>, _, 0, [{NewSection, NewCount}|Rest], State, Acc) ->
    from_binary_resources(Tail, NewSection, NewCount, Rest, State, Acc);
from_binary_resources(<<>>, _, _, _, State, Acc) ->
    error({truncated_message, State, Acc});
from_binary_resources(<<Data/binary>>, Section, Count, RestCounts, State0 = #bin_state{offset=Offset0,invalid_resources=Invalid,quit_on_error=Quit}, Acc) ->
    case
        case binary_to_domain(Data) of
            {_, TmpDomain, TmpTail} ->
                % It's possible that decompression produces an error.
                % Because the domain was otherwise valid, we can skip the resource
                % and just count the errors
                case decompress_domain(TmpDomain, State0) of
                    {ok, Decompressed} -> {Decompressed, is_tuple(TmpDomain), domain_binary_length(TmpDomain), TmpTail};
                    {error, _} when Quit -> error({invalid_domain, invalid_compression, State0, Acc});
                    {error, _} ->
                        %% Invalid compression, but we can skip the question
                        {error, domain_binary_length(TmpDomain) + 1, TmpTail}
                end;
            {error, truncated_domain} -> error({truncated_domain, State0, Acc});
            {error, Reason} -> error({invalid_domain, Reason, State0, Acc})
        end
    of
        {Domain, true, DomainBytes, Tail} ->
            State1 = add_domain_ref(Domain, Offset0, DomainBytes - 2, State0),
            from_binary_resource_data(Tail, Section, Count, RestCounts, Domain, DomainBytes, Acc, State1);
        {Domain, false, DomainBytes, Tail} ->
            State1 = add_domain_ref(Domain, Offset0, DomainBytes, State0),
            from_binary_resource_data(Tail, Section, Count, RestCounts, Domain, DomainBytes, Acc, State1);
        {error, DomainBytes, Tail} ->
            case Tail of
                <<_:16, _:16, _:32, DataLen:16, _:DataLen/binary, Rest/binary>> ->
                    % Discard the resource, continue
                    from_binary_resources(Rest, Section, Count - 1, RestCounts, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen,invalid_resources=Invalid+1}, [invalid|Acc]);
                _ -> error({truncated_resource_data, State0, Acc})
            end
    end.


from_binary_payload(Data, [{question, QuestionCount}|OtherCounts]=Counts, State0) ->
    {ok, Tail, State1, Acc} = from_binary_questions(Data, QuestionCount, OtherCounts, State0, []),
    Fn = fun (Count, RecordList) -> lists:split(Count, RecordList) end,
    {SplitRecords, []} = lists:mapfoldl(Fn, Acc, lists:reverse([GenCount || {_, GenCount} <- Counts])),
    [Additional, Nameservers, Answers, Questions] = SplitRecords,
    {ok, {Questions, Answers, Nameservers, Additional}, Tail, State1}.


from_binary_edns(Msg = #{'Additional' := Additional, 'Return_code' := ReturnCode}) when length(Additional) =:= 0 ->
    {ok, Msg#{'Return_code' => return_code(ReturnCode)}};
from_binary_edns(Msg = #{'Additional' := Additional0, 'Return_code' := RCode}) ->
    % Search for opt
    case lists:partition(fun ({_, Type, _, _, _}) -> Type =:= opt end, Additional0) of
        {[], _} -> {ok, Msg#{'Return_code' => return_code(RCode)}};
        {[{[], opt, Class, Ttl, Data}], Additional1} ->
            UDPSize = case dnsclass:from_to(Class, atom, value) of
                UDPSizeValue when UDPSizeValue < 512 -> 512;
                UDPSizeValue -> UDPSizeValue
            end,
            <<RCodeHigh, Version, DNSSecOK:1, _Z:15>> = <<Ttl:32>>,
            % Allow dnsopt key-value pairs to modify this map?
            % We could also just make maps:from_list and smush it to the current map...
            % Or smush the current map to that one.
            case Version of
                0 ->
                    try dnsopt:from_binary(Data) of
                        {ok, Map} ->
                            {ok, Msg#{
                                'EDNS_version' => Version,
                                'EDNS_dnssec_ok' => boolean(DNSSecOK),
                                'EDNS_udp_payload_size' => UDPSize,
                                'Return_code' => return_code((RCodeHigh bsl 4) bor RCode),
                                'EDNS' => Map,
                                'Additional' => Additional1
                            }}
                    catch
                        error:function_clause -> {error, invalid_data}
                    end;
                _ -> {error, bad_version}
            end;
        {OptList, _} when length(OptList) > 1 -> {error, multiple_opts}
    end.


from_binary_header(?HEADER) ->
    Msg = #{
        'ID'                  => Id,
        'Is_response'         => boolean(IsResponse),
        'Opcode'              => opcode(OpCode),
        'Authoritative'       => boolean(Authoritative),
        'Truncated'           => boolean(Truncated),
        'Recursion_desired'   => boolean(RecursionDesired),
        'Recursion_available' => boolean(RecursionAvailable),
        'Authenticated_data'  => boolean(AuthData),
        'Checking_disabled'   => boolean(CheckingDisabled),
        'Reserved'            => Reserved,
        'Return_code'         => ResponseCode,
        'Questions'           => [],
        'Answers'             => [],
        'Nameservers'         => [],
        'Additional'          => []
    },
    case Msg of
        #{'Is_response' := true} -> Msg;
        _ ->
            Msg#{'Response' => #{
                'Answers'         => [],
                'Nameservers'     => [],
                'Additional'      => []
            }}
    end.


-type from_binary_error_specific() ::
    {'invalid_resource_data', binary()} |
    'invalid_domain'                    |
    'truncated_domain'                  |
    'truncated_message'.
-type from_binary_error() ::
      {'format_error', from_binary_error_specific()}
    | {'edns_error', 'bad_version' | 'multiple_opts' | 'invalid_data'}.
-spec from_binary(Bin :: binary() | [byte()]) ->
      {'ok', Msg :: dnslib:message(), TrailingBytes :: binary()}
    | {'error', 'too_short'} % Message wasn't long enough to represent DNS header
    | {'error', from_binary_error(), Response :: dnsmsg:message()}.
from_binary(Bin) ->
    from_binary(Bin, #{}).


from_binary(BinList, Opts) when is_list(BinList) ->
    from_binary(list_to_binary(BinList), Opts);
from_binary(MessageBin = <<BinHeader:4/binary,QuestionCount:16,AnswerCount:16,NameserverCount:16,AdditionalCount:16,BinData/binary>>, _Opts) ->
    #{'Is_response' := IsResponse} = Msg0 = from_binary_header(BinHeader),
    Counts = [{question, QuestionCount}, {answer, AnswerCount}, {authority, NameserverCount}, {additional, AdditionalCount}],
    try from_binary_payload(BinData, Counts, #bin_state{message_bin=MessageBin}) of
        {ok, {Questions, Answers, Nameservers, Additional}, Tail, State} ->
            Msg1 = Msg0#{
                'Questions'   := [Tuple || Tuple <- Questions,   Tuple =/= invalid],
                'Answers'     := [Tuple || Tuple <- Answers,     Tuple =/= invalid],
                'Nameservers' := [Tuple || Tuple <- Nameservers, Tuple =/= invalid],
                'Additional'  := [Tuple || Tuple <- Additional,  Tuple =/= invalid]
            },
            % What if there are duplicate questions? Or other insanity?
            %
            % Could we elevate OPT record here to a member of the message?
            % Sanity check contents?
            % And while doing that, allow record modules to modify the message?
            % Though that seems perilious... Make an exception for OPT and not
            % others?
            %
            % edns can still produce a format_error...
            case from_binary_edns(Msg1) of
                {ok, Msg2} ->
                    case State of
                        #bin_state{invalid_resources=0,invalid_questions=0} -> {ok, Msg2, Tail}
                        %#bin_state{invalid_resources=IQ,invalid_questions=IR} ->
                        %    {error, {format_error, invalid_data}, Msg1#{'Resource_errors' => IQ + IR}}
                    end;
                {error, Reason} ->
                    ReturnMsg = if
                        not IsResponse ->
                            case Reason of
                                bad_version -> dnsmsg:set_response_header(Msg0, [{return_code, bad_version}]);
                                _ -> dnsmsg:set_response_header(Msg0, [{return_code, format_error}])
                            end;
                        IsResponse -> Msg0
                    end,
                    % Set return code as undefined, as the EDNS error causes us to not really know what is going on.
                    % If a response is produced, that will include the return_code regardless of what we stick
                    % in the returned message
                    {error, {edns_error, Reason}, ReturnMsg#{'Return_code' => undefined}}
            end
    catch
        error:{truncated_message, State, Acc}                       -> from_binary_error_return(truncated_message, Counts, Acc, Msg0, State);
        error:{invalid_domain, Reason, State, Acc}                  -> from_binary_error_return({invalid_domain, Reason}, Counts, Acc, Msg0, State);
        error:{truncated_domain, State, Acc}                        -> from_binary_error_return(truncated_domain, Counts, Acc, Msg0, State);
        error:{invalid_question_class, Type, Class, State, Acc}     -> from_binary_error_return({invalid_question_class, Type, Class}, Counts, Acc, Msg0, State);
        error:{truncated_resource_data, State, Acc}                 -> from_binary_error_return(truncated_resource_data, Counts, Acc, Msg0, State);
        error:{invalid_resource_class, Type, Class, State, Acc}     -> from_binary_error_return({invalid_resource_class, Type, Class}, Counts, Acc, Msg0, State);
        error:{invalid_section, Type, Section, State, Acc}          -> from_binary_error_return({invalid_section, Type, Section}, Counts, Acc, Msg0, State);
        error:{invalid_resource_data, Type, RData, State, Acc}      -> from_binary_error_return({invalid_resource_data, Type, RData}, Counts, Acc, Msg0, State)
    end;
from_binary(<<_/bits>>, _) ->
    {error, too_short}.
%from_binary(_, _) ->
%    {error, badarg}.


from_binary_error_return(ErrSpec, Counts, Acc, Msg = #{'Is_response' := IsResponse}, State) ->
    %{error, {format_error, ErrSpec}, prepare_error_msg_return(Counts, Acc, Msg, State)}.
    ReturnMsg = if
        not IsResponse -> dnsmsg:set_response_header(Msg, [{return_code, format_error}]);
        IsResponse -> Msg
    end,
    {error, {format_error, ErrSpec}, ReturnMsg}.


prepare_error_msg_return(Counts, Acc0, Msg, _) ->
    % Collect sections from acc based on Counts
    Acc = lists:reverse(Acc0),
    Fn = fun
        (Count, FunList) when length(FunList) > Count -> lists:split(Count, FunList);
        (_, []) -> {[], []};
        (_, FunList) -> {FunList, []}
    end,
    {Entries0, []} = lists:mapfoldl(Fn, Acc, Counts),
    [Questions, Answers, Nameservers, Additional] = lists:map(fun (EntryList) -> [Tuple || Tuple <- lists:reverse(EntryList), Tuple =/= undefined] end, Entries0),
    Msg#{
        'Questions'   => Questions,
        'Answers'     => Answers,
        'Nameservers' => Nameservers,
        'Additional'  => Additional
    }.


to_bin_questions([], Acc, State) ->
    {ok, lists:reverse(Acc), State};
to_bin_questions([{Domain0, Type, Class}|Rest], Acc, State0 = #bin_state{max_length=MaxLength,compress=AllowCompress}) ->
    {Domain1, State1=#bin_state{offset=Offset}} = compress_domain(Domain0, AllowCompress, State0),
    Entry = <<Domain1/binary, (dnsrr:from_to(Type, atom, value)):16, (dnsclass:from_to(Class, atom, value)):16>>,
    case Offset + 4 =< MaxLength of
        true -> to_bin_questions(Rest, [Entry|Acc], State1#bin_state{offset=Offset+4});
        false -> {length_exhausted, lists:reverse(Acc), State0}
    end.


to_bin_records([], Acc, State) ->
    {ok, lists:reverse(Acc), State};
to_bin_records([{Domain0, Type, Class, Ttl, Data}|Rest], Acc, State0 = #bin_state{max_length=MaxLength,compress=AllowCompress}) ->
    {Domain1, State1=#bin_state{offset=Offset0}} = compress_domain(Domain0, AllowCompress, State0),
    case
        case dnsrr:from_to(Type, atom, module) of
            Type when is_integer(Type), is_binary(Data) ->
                BinLen = byte_size(Data),
                {Data, BinLen, Type, State1#bin_state{offset=Offset0+10+BinLen}};
            Module ->
                case Module:to_binary(Data) of
                    {domains, CompressList} ->
                        {Bin, BinLen, TmpState} = compress_datalist(CompressList, [], State1#bin_state{offset=Offset0+10}),
                        {Bin, BinLen, dnsrr:from_to(Module, module, value), TmpState};
                    {ok, Bin} ->
                        BinLen = iolist_size(Bin),
                        {Bin, BinLen, dnsrr:from_to(Module, module, value), State1#bin_state{offset=Offset0+10+BinLen}}
                end
        end
    of
        {_, _, _, #bin_state{offset=Offset1}} when Offset1 > MaxLength -> {length_exhausted, lists:reverse(Acc), State0};
        {RData, RDataLen, TypeValue, State2} ->
            Entry = [<<Domain1/binary, TypeValue:16, (dnsclass:from_to(Class, atom, value)):16, Ttl:32, RDataLen:16>>, RData],
            to_bin_records(Rest, [Entry|Acc], State2)
    end.


to_binary_edns(Msg = #{'EDNS' := Map}, _) ->
    #{
        'EDNS_version' := Version,
        'EDNS_udp_payload_size' := MaxSize,
        'EDNS_dnssec_ok' := DNSSecOK,
        'Return_code' := ReturnCode0
    } = Msg,
    Mod = dnsrr:from_to(opt, atom, module),
    ReturnCode1 = return_code(ReturnCode0),
    % Had we other fields in the map (like DNS Cookie), we'd have to
    % produce a list of those for the entry data
    <<Ttl:32>> = <<(ReturnCode1 bsr 4), Version, (boolean(DNSSecOK)):1, 0:15>>,
    {ok, Data} = dnsopt:to_binary(Map),
    {ok, DataIolist} = Mod:to_binary(Data),
    Entry = [<<0, (Mod:value()):16, MaxSize:16, Ttl:32, (iolist_size(DataIolist)):16>>, DataIolist],
    {Entry, iolist_size(Entry), Msg#{'Return_code' => ReturnCode1 band 16#0F}};
to_binary_edns(Msg = #{'Return_code' := ReturnCode}, _) ->
    {<<>>, 0, Msg#{'Return_code' => return_code(ReturnCode)}}.


reserve_edns_bytes(State = #bin_state{edns=false}, _) ->
    {State, false};
reserve_edns_bytes(State = #bin_state{max_length=MaxLength}, ReserveBytes) ->
    case MaxLength - 12 > ReserveBytes of
        true -> {State#bin_state{max_length=MaxLength - ReserveBytes}, true};
        false -> {State, false}
    end.


-spec to_binary(dns:message()) ->
    {'ok', Length :: 12..65535, Bin :: binary()} |
    {
        'partial',
        Length :: 12..65535,
        Bin :: binary(),
        {
            RemainingQuestions   :: [dnslib:question()],
            RemainingAnswers     :: [dnslib:resource()],
            RemainingNameservers :: [dnslib:resource()],
            RemainingAdditional  :: [dnslib:resource()]
        }
    }.
to_binary(Msg) ->
    to_binary(Msg, []).


-spec to_binary(dns:message(), Opts :: list()) ->
    {'ok', Length :: 12..65535, Bin :: binary()} |
    {
        'partial',
        Length :: 12..65535,
        Bin :: binary(),
        {
            RemainingQuestions   :: [dnslib:question()],
            RemainingAnswers     :: [dnslib:resource()],
            RemainingNameservers :: [dnslib:resource()],
            RemainingAdditional  :: [dnslib:resource()]
        }
    }.
to_binary(Msg, Opts) ->
    case to_iolist(Msg, Opts) of
        {ok, Len, IoList} -> {ok, Len, iolist_to_binary(IoList)};
        {partial, Len, IoList, Remaining} -> {partial, Len, iolist_to_binary(IoList), Remaining}
    end.


-spec to_iolist(dns:message()) ->
    {'ok', Length :: 12..65535, Bin :: iolist()} |
    {
        'partial',
        Length :: 12..65535,
        Bin :: iolist(),
        {
            RemainingQuestions   :: [dnslib:question()],
            RemainingAnswers     :: [dnslib:resource()],
            RemainingNameservers :: [dnslib:resource()],
            RemainingAdditional  :: [dnslib:resource()]
        }
    }.
to_iolist(Msg) ->
    to_iolist(Msg, []).


-spec to_iolist(dns:message(), Opts :: list()) ->
    {'ok', Length :: 12..65535, Bin :: iolist()} |
    {
        'partial',
        Length :: 12..65535,
        Bin :: iolist(),
        {
            RemainingQuestions   :: [dnslib:question()],
            RemainingAnswers     :: [dnslib:resource()],
            RemainingNameservers :: [dnslib:resource()],
            RemainingAdditional  :: [dnslib:resource()]
        }
    }.
to_iolist(Msg0, Opts) ->
    % If the total length of the message is restricted, we should still always fit opt there?
    % Or allow caller to specify in Opts if the opt record should be prioritized?
    State0 = to_bin_opts_to_state(#bin_state{}, Opts),
    {EdnsBin, EdnsBinLen, Msg1} = to_binary_edns(Msg0, Opts),
    {State, AddEdns} = reserve_edns_bytes(State0, EdnsBinLen),
    #{
        'Questions'   := Questions0,
        'Answers'     := Answers0,
        'Nameservers' := Nameservers0,
        'Additional'  := Additional0
    } = Msg1,
    QuestionCount = length(Questions0),
    true = QuestionCount =< 16#FFFF,
    Questions1 = lists:reverse(Questions0),
    Answers1 = lists:reverse(Answers0),
    Nameservers1 = lists:reverse(Nameservers0),
    Additional1 = lists:reverse(Additional0),
    case to_bin_questions(Questions1, [], State) of
        {length_exhausted, QuestionsBin, #bin_state{offset=Rlen,truncate=Truncate}} ->
            {ok, Header} = to_bin_header(dnsmsg:set_header(Msg1, truncated, Truncate)),
            % Add an error for situations where max_length is too small to fit a sane messages (at least one question?)
            {_, RemainingQuestions} = lists:split(length(QuestionsBin), Questions1),
            if
                AddEdns -> {partial, Rlen+EdnsBinLen, [Header, <<(length(QuestionsBin)):16, 0:32, 1:16>>, QuestionsBin, EdnsBin], {RemainingQuestions, Answers1, Nameservers1, Additional1}};
                true -> {partial, Rlen, [Header, <<(length(QuestionsBin)):16, 0:48>>, QuestionsBin], {RemainingQuestions, Answers1, Nameservers1, Additional1}}
            end;
        {ok, QuestionsBin, State1} ->
            Resources = [Answers1, Nameservers1, Additional1],
            case to_bin_records(lists:append(Resources), [], State1) of
                {ok, Records, #bin_state{offset=Rlen}} ->
                    {ok, Header} = to_bin_header(Msg1),
                    AnswerCount = length(Answers0),
                    true = AnswerCount =< 16#FFFF,
                    NameserverCount = length(Nameservers0),
                    true = NameserverCount =< 16#FFFF,
                    AdditionalCount = length(Additional0),
                    if
                        AddEdns ->
                            true = AdditionalCount =< 16#FFFF - 1,
                            Counts = <<AnswerCount:16, NameserverCount:16, (AdditionalCount+1):16>>,
                            {ok, Rlen+EdnsBinLen, [Header, <<QuestionCount:16>>, Counts, QuestionsBin, Records, EdnsBin]};
                        true ->
                            true = AdditionalCount =< 16#FFFF,
                            Counts = <<AnswerCount:16, NameserverCount:16, AdditionalCount:16>>,
                            {ok, Rlen, [Header, <<QuestionCount:16>>, Counts, QuestionsBin, Records]}
                    end;
                {length_exhausted, ResourcesBin, #bin_state{offset=Rlen,truncate=Truncate}} ->
                    {ok, Header} = to_bin_header(dnsmsg:set_header(Msg1, truncated, Truncate)),
                    % Add an error for situations where max_length is too small to fit a sane messages (at least one question?)
                    {Resources1, _} = lists:mapfoldl(fun (List, Count) -> SplitN = min(length(List), Count), {_, Remaining} = lists:split(SplitN, List), {Remaining, Count - SplitN} end, length(ResourcesBin), Resources),
                    [
                        {AnswerCount, RemainingAnswers},
                        {NameserverCount, RemainingNameservers},
                        {AdditionalCount, RemainingAdditional}
                    ] = [{length(Total) - length(Remaining), Remaining} || {Total, Remaining} <- lists:zip(Resources, Resources1)],
                    true = AnswerCount =< 16#FFFF,
                    true = NameserverCount =< 16#FFFF,
                    if
                        AddEdns ->
                            true = AdditionalCount =< 16#FFFF - 1,
                            Counts = <<AnswerCount:16, NameserverCount:16, (AdditionalCount+1):16>>,
                            {partial, Rlen+EdnsBinLen, [Header, <<QuestionCount:16>>, Counts, QuestionsBin, ResourcesBin, EdnsBin], {[], RemainingAnswers, RemainingNameservers, RemainingAdditional}};
                        true ->
                            true = AdditionalCount =< 16#FFFF,
                            Counts = <<AnswerCount:16, NameserverCount:16, AdditionalCount:16>>,
                            {partial, Rlen, [Header, <<QuestionCount:16>>, Counts, QuestionsBin, ResourcesBin], {[], RemainingAnswers, RemainingNameservers, RemainingAdditional}}
                    end
            end
    end.


to_bin_opts_to_state(State = #bin_state{}, []) ->
    State;
% Add an option to produce normalized domains by default
to_bin_opts_to_state(State = #bin_state{}, [{max_length, Length}|Rest]) when Length >= 12, Length =< 16#FFFF ->
    to_bin_opts_to_state(State#bin_state{max_length=Length}, Rest);
to_bin_opts_to_state(State = #bin_state{}, [{edns, Boolean}|Rest]) when Boolean =:= true; Boolean =:= false ->
    to_bin_opts_to_state(State#bin_state{edns=Boolean}, Rest);
to_bin_opts_to_state(State = #bin_state{}, [{domain_compression, Boolean}|Rest]) when Boolean =:= true; Boolean =:= false ->
    to_bin_opts_to_state(State#bin_state{compress=Boolean,compress_rdata=Boolean}, Rest);
to_bin_opts_to_state(State = #bin_state{}, [{data_domain_compression, Boolean}|Rest]) when Boolean =:= true; Boolean =:= false ->
    to_bin_opts_to_state(State#bin_state{compress_rdata=Boolean}, Rest);
to_bin_opts_to_state(State = #bin_state{}, [{truncate, Boolean}|Rest]) when Boolean =:= true; Boolean =:= false ->
    to_bin_opts_to_state(State#bin_state{truncate=Boolean}, Rest).


-spec to_bin_header(Msg :: dnsmsg:message()) -> {'ok', binary()}.
to_bin_header(Msg = #{'Reserved' := Reserved}) when bit_size(Reserved) =:= 1 ->
    #{
        'ID'                  := Id,
        'Is_response'         := IsResponse,
        'Opcode'              := Opcode,
        'Authoritative'       := Authoritative,
        'Truncated'           := Truncated,
        'Recursion_desired'   := RecursionDesired,
        'Recursion_available' := RecursionAvailable,
        'Reserved'            := Reserved,
        'Authenticated_data'  := AuthData,
        'Checking_disabled'   := CheckingDisabled,
        'Return_code'         := ReturnCode
    } = Msg,
    {ok, <<
        Id:16,
        (boolean(IsResponse)):1,
        (opcode(Opcode)):4,
        (boolean(Authoritative)):1,
        (boolean(Truncated)):1,
        (boolean(RecursionDesired)):1,
        (boolean(RecursionAvailable)):1,
        Reserved/bits,
        (boolean(AuthData)):1,
        (boolean(CheckingDisabled)):1,
        ReturnCode:4
    >>}.


-spec to_binary_domain(dnslib:domain(), boolean()) -> {'domain', Compress :: false, dnslib:domain()}.
to_binary_domain(Domain, AllowCompression) ->
    {domain, AllowCompression, Domain}.


-spec from_binary_domain(dnslib:domain() | dnslib:compressed_domain(), Offset :: non_neg_integer())
    -> {'domain', dnslib:domain(), non_neg_integer()}
     | {'compressed', non_neg_integer(), dnslib:domain(), non_neg_integer()}.
from_binary_domain({compressed, Ref, Acc}, Offset) ->
    {compressed, Ref, Acc, Offset};
from_binary_domain(Domain, Offset) ->
    {domain, Domain, Offset}.
