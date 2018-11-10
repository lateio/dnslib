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
% This file allows DNS message to be serialized to and parsed from binary
% wire format.
-module(dnswire).

-export([
    from_binary/1,
    to_binary/1,
    to_binary/2,
    to_iolist/1,
    to_iolist/2,
    indicate_domain/1,
    indicate_domain/2,
    indicate_domain_compress/1,
    indicate_domain_decompress/2,
    return_code/1,
    opcode/1
]).

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
return_code({undefined, Value}) -> Value;
return_code(Value) -> {undefined, Value}.


opcode(0) -> query;   %% RFC1035
opcode(1) -> i_query; %% RFC1035
opcode(2) -> status;  %% RFC1035
%opcode(3) -> unassigned
%opcode(4) -> notify;  %% RFC1996
%opcode(5) -> update;  %% RFC2136

opcode(query)   -> 0; %% RFC1035
opcode(i_query) -> 1; %% RFC1035
opcode(status)  -> 2; %% RFC1035
%opcode(notify)  -> 4; %% RFC1996
%opcode(update)  -> 5; %% RFC2136
opcode({undefined, Value}) -> Value;
opcode(Value) -> {undefined, Value}.


% Header
-define(HEADER,
<<
	Id:16,
	IsResponse:1, OpCode:4, Authoritative:1, Truncated:1, RecursionDesired:1, RecursionAvailable:1, Reserved:1, AuthData:1, CheckingDisabled:1, ResponseCode:4
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
    trie=dnstrie:new() :: dnstrie:trie(),
    refs=[] :: [{{non_neg_integer(),pos_integer()},dnslib:domain()}],
    compress=true :: boolean(),
    compress_rdata=true :: boolean(),
    quit_on_error=true :: boolean(),
    message_bin :: binary() | 'undefined',
    invalid_questions=0 :: non_neg_integer(),
    invalid_resources=0 :: non_neg_integer()
}).


% There's literally no point adding refs for root domain. It should not be considered when/for compression
% But as it's possible to Ref to a root domain, we'll still keep those refs around...
%add_domain_ref([], _, _, State) ->
%    State;
add_domain_ref(Domain, DomainOffset, DomainBytes, State = #bin_state{refs=Refs}) ->
    % Although DomainBytes =/= dnslib:domain_binary_length(Domain),
    % compression reference has to refer to a byte that's actually physically
    % present in the domain. Thus we can use DomainBytes as the
    % "length" of the domain in Refs
    State#bin_state{refs=[{{DomainOffset,DomainBytes},Domain}|Refs]}.


compress_domain([], _, State = #bin_state{offset=Offset}) ->
    % No reason to compress root domain
    {<<0>>, State#bin_state{offset=Offset+1}};
compress_domain(Domain, _, State = #bin_state{compress=false,offset=Offset}) ->
    Bin = dnslib:domain_to_binary(Domain),
    {Bin, State#bin_state{offset=Offset+byte_size(Bin)}};
compress_domain(Domain, Compress, State0 = #bin_state{trie=Trie0,offset=Offset0}) ->
    case dnstrie:get_path(lists:reverse(Domain), Trie0) of
        {full, [Ref|_]} when Compress -> {<<3:2, Ref:14>>, State0#bin_state{offset=Offset0+2}};
        {full, _} ->
            Bin = dnslib:domain_to_binary(Domain),
            {Bin, State0#bin_state{offset=Offset0+byte_size(Bin)}};
        {partial, Match = [Ref|_]} ->
            Diff = length(Domain) - length(Match),
            State1 = #bin_state{offset=Offset1} = populate_compression_trie(Domain, Diff, State0),
            case Compress of
                true ->
                    {NewLabels, _} = lists:split(Diff, Domain),
                    Bin0 = dnslib:domain_to_binary(NewLabels),
                    LengthSansZero = byte_size(Bin0) - 1,
                    <<Bin:LengthSansZero/binary, _/binary>> = Bin0,
                    {<<Bin/binary, 3:2, Ref:14>>, State1#bin_state{offset=Offset1+2}};
                false ->
                    Bin = dnslib:domain_to_binary(Domain),
                    {Bin, State1#bin_state{offset=Offset0+byte_size(Bin)}}
            end;
        {none, []} ->
            State1 = #bin_state{offset=Offset1} = populate_compression_trie(Domain, length(Domain), State0),
            Bin = dnslib:domain_to_binary(Domain),
            {Bin, State1#bin_state{offset=Offset1+1}}
    end.


populate_compression_trie(_, 0, State) ->
    State;
populate_compression_trie(Domain = [Label|Next], Limit, State = #bin_state{offset=Offset,trie=Trie}) ->
    populate_compression_trie(Next, Limit-1, State#bin_state{trie=dnstrie:set(lists:reverse(Domain),Offset,Trie),offset=Offset+1+byte_size(Label)}).


compress_datalist([], Acc, State) ->
    RData = lists:reverse(Acc),
    {RData, iolist_size(RData), State};
compress_datalist([{domain, _, Domain}|Rest], Acc, State = #bin_state{compress_rdata=false}) ->
    compress_datalist(Rest, [Domain|Acc], State);
compress_datalist([{domain, Compress, Domain0}|Rest], Acc, State0) ->
    {Domain1, State1} = compress_domain(Domain0, Compress, State0),
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
                {ok, Domain} -> {ok, Domain};
                _ -> {error, invalid_compression}
            end;
        {Ref, Domain} -> {ok, lists:append(lists:reverse(Acc), Domain)};
        {DomainStart, SuperDomain} ->
            case find_ref_in_domain(Ref, DomainStart, SuperDomain) of
                undefined -> {error, error_invalid_compression};
                {Ref, Domain} -> {ok, lists:append(lists:reverse(Acc), Domain)}
            end
    end.


decompress_domain_from_binary({compressed, Ref, _}, Offset, _) when Ref >= Offset ->
    {error, forward_reference};
decompress_domain_from_binary({compressed, Ref, Acc}, _, MessageBin) ->
    <<_:Ref/binary, Bin/binary>> = MessageBin,
    case dnslib:binary_to_domain(Bin) of
        {{compressed, NewRef, NewAcc}, _} -> decompress_domain_from_binary({compressed, NewRef, [NewAcc|Acc]}, Ref, MessageBin);
        {ok, Domain, _} -> {ok, lists:append(lists:reverse(Acc), Domain)}
    end.


decompress_ref_datalist([], Acc, State) ->
    {ok, lists:reverse(Acc), State};
decompress_ref_datalist([{domain, Domain, DomainOffset}|Rest], Acc, State0 = #bin_state{offset=Offset}) ->
    State1 = add_domain_ref(Domain, Offset+DomainOffset, dnslib:domain_binary_length(Domain), State0),
    decompress_ref_datalist(Rest, [Domain|Acc], State1);
decompress_ref_datalist([{compressed, _, DomainAcc, DomainOffset}=Tuple|Rest], Acc, State0 = #bin_state{offset=Offset}) ->
    % We need to add ref to this domain...
    case decompress_domain(Tuple, State0) of
        {ok, Domain} ->
            State1 = add_domain_ref(Domain, Offset+DomainOffset, dnslib:domain_binary_length(DomainAcc), State0),
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


from_binary_questions(Data, [0, OtherCounts], State, Acc) ->
    from_binary_resources(Data, OtherCounts, State, Acc);
from_binary_questions(<<>>, _, State, Acc) ->
    error({truncated_message, State, Acc});
from_binary_questions(Data, [Count|OtherCounts], State0 = #bin_state{offset=Offset,invalid_questions=Invalid,quit_on_error=Quit}, Acc) ->
    case
        case dnslib:binary_to_domain(Data) of
            {ok, TmpDomain, TmpTail} -> {TmpDomain, false, dnslib:domain_binary_length(TmpDomain), TmpTail};
            {{compressed, _, TmpDomain} = Tuple, TmpTail} ->
                case decompress_domain(Tuple, State0) of
                    {ok, Decompressed} -> {Decompressed, true, dnslib:domain_binary_length(TmpDomain) + 1, TmpTail};
                    {error, _} when Quit -> error({invalid_domain, State0, Acc});
                    {error, _} ->
                        %% Invalid compression, but we can skip the question
                        {error, dnslib:domain_binary_length(TmpDomain) + 1, TmpTail}
                end;
            {error, truncated_domain} -> error({truncated_domain, State0, Acc});
            {error, Reason} -> error({invalid_domain, Reason, State0, Acc})
        end
    of
        {Domain, WasCompressed, DomainBytes, Tail} ->
            DomainRefBytes = case WasCompressed of
                true -> DomainBytes - 1;
                false -> DomainBytes
            end,
            case Tail of
                <<TypeValue:16, ClassValue:16, Rest/binary>> ->
                    Type = dnsrr:from_to(TypeValue, value, atom),
                    Class = dnsclass:from_to(ClassValue, value, atom),
                    case dnsrr:class_valid_for_type(Class, Type) of
                        false when Quit -> error({invalid_question_class, Type, Class, State0, Acc});
                        false -> from_binary_questions(Rest, [Count - 1|OtherCounts], State0#bin_state{offset=Offset + DomainBytes + 4, invalid_questions=Invalid+1}, [invalid|Acc]);
                        true ->
                            State1 = add_domain_ref(Domain, Offset, DomainRefBytes, State0),
                            Entry = {Domain, Type, Class},
                            from_binary_questions(Rest, [Count - 1|OtherCounts], State1#bin_state{offset=Offset + DomainBytes + 4}, [Entry|Acc])
                    end;
                _ -> error({truncated_resource_data, State0, Acc})
            end;
        {error, DomainBytes, Tail} ->
            case Tail of
                <<_:16, _:16, Rest/binary>> ->
                    from_binary_questions(Rest, [Count - 1|OtherCounts], State0#bin_state{offset=Offset + DomainBytes + 4, invalid_questions=Invalid+1}, [invalid|Acc]);
                _ -> error({truncated_resource_data, State0, Acc})
            end
    end.

-define(RMATCH, <<Type0:16, Class0:16, Ttl:32, DataLen:16, RData:DataLen/binary, Rest/binary>>).
from_binary_resource_data(?RMATCH, Count, Domain, DomainBytes, Acc, State0 = #bin_state{offset=Offset0,invalid_resources=Invalid,quit_on_error=Quit}) ->
    Class = dnsclass:from_to(Class0, value, atom),
    case dnsrr:from_to(Type0, value, module) of
        Type0 ->
            Entry = {Domain, Type0, Class, Ttl, RData},
            from_binary_resources(Rest, Count - 1, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen}, [Entry|Acc]);
        Module ->
            Type = Module:atom(),
            % Even if we get an opt resource, we can't apply it
            % to the message here...
            % Just handle it when handling the query?
            % Start with additional records
            case dnsrr:class_valid_for_type(Class, Type) of
                false when Quit -> error({invalid_resource_class, Type, Class, State0, Acc});
                false -> from_binary_resources(Rest, Count - 1, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen,invalid_resources=Invalid+1}, [invalid|Acc]);
                true ->
                    case Module:from_binary(RData) of
                        {error, _} when Quit -> error({invalid_resource_data, Type, RData, State0, Acc});
                        {error, _} -> from_binary_resources(Rest, Count - 1, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen,invalid_resources=Invalid+1}, [invalid|Acc]);
                        {ok, EntryData} ->
                            Entry = {Domain, Type, Class, Ttl, EntryData},
                            from_binary_resources(Rest, Count - 1, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen}, [Entry|Acc]);
                        {domains, DecompRefList} ->
                            % It's possible that decompression produces an error. We should be prepared to handle that...
                            case decompress_ref_datalist(DecompRefList, [], State0#bin_state{offset=Offset0+DomainBytes+10}) of
                                {ok, DataList, State1 = #bin_state{offset=Offset1}} ->
                                    {ok, EntryData} = Module:from_binary_finalize(DataList),
                                    Entry = {Domain, Type, Class, Ttl, EntryData},
                                    from_binary_resources(Rest, Count - 1, State1#bin_state{offset=Offset1 + DataLen}, [Entry|Acc]);
                                _ when Quit -> error({invalid_resource_data, Type, RData, State0, Acc});
                                _ ->
                                    from_binary_resources(Rest, Count - 1, State0#bin_state{offset=Offset0 + DataLen, invalid_resources=Invalid+1}, [invalid|Acc])
                                    % Continue. Although the resource is invalid, we can handle rest of the message
                            end
                    end
            end
    end;
from_binary_resource_data(_, _, _, _, Acc, State0) ->
    error({truncated_resource_data, State0, Acc}).


from_binary_resources(Tail, 0, State, Acc) ->
    {ok, Tail, State, Acc};
from_binary_resources(<<>>, _, State, Acc) ->
    error({truncated_message, State, Acc});
from_binary_resources(Data, Count, State0 = #bin_state{offset=Offset0,invalid_resources=Invalid,quit_on_error=Quit}, Acc) ->
    case
        case dnslib:binary_to_domain(Data) of
            {ok, TmpDomain, TmpTail} -> {TmpDomain, false, dnslib:domain_binary_length(TmpDomain), TmpTail};
            {{compressed, _, TmpDomain} = Tuple, TmpTail} ->
                % It's possible that decompression produces an error.
                % Because the domain was otherwise valid, we can skip the resource
                % and just count the errors
                case decompress_domain(Tuple, State0) of
                    {ok, Decompressed} -> {Decompressed, true, dnslib:domain_binary_length(TmpDomain) + 1, TmpTail};
                    {error, _} when Quit -> error({invalid_domain, invalid_compression, State0, Acc});
                    {error, _} ->
                        %% Invalid compression, but we can skip the question
                        {error, dnslib:domain_binary_length(TmpDomain) + 1, TmpTail}
                end;
            {error, truncated_domain} -> error({truncated_domain, State0, Acc});
            {error, Reason} -> error({invalid_domain, Reason, State0, Acc})
        end
    of
        {Domain, true, DomainBytes, Tail} ->
            State1 = add_domain_ref(Domain, Offset0, DomainBytes - 1, State0),
            from_binary_resource_data(Tail, Count, Domain, DomainBytes, Acc, State1);
        {Domain, false, DomainBytes, Tail} ->
            State1 = add_domain_ref(Domain, Offset0, DomainBytes, State0),
            from_binary_resource_data(Tail, Count, Domain, DomainBytes, Acc, State1);
        {error, DomainBytes, Tail} ->
            case Tail of
                <<_:16, _:16, _:32, DataLen:16, _:DataLen/binary, Rest/binary>> ->
                    % Discard the resource, continue
                    from_binary_resources(Rest, Count - 1, State0#bin_state{offset=Offset0 + DomainBytes + 10 + DataLen,invalid_resources=Invalid+1}, [invalid|Acc]);
                _ -> error({truncated_resource_data, State0, Acc})
            end
    end.


from_binary_payload(Data, Counts = [QuestionCount|OtherCounts], State0) ->
    TotalCount = lists:foldl(fun (Count, Total) -> Total + Count end, 0, OtherCounts),
    {ok, Tail, State1, Acc} = from_binary_questions(Data, [QuestionCount, TotalCount], State0, []),
    Fn = fun (Count, RecordList) -> lists:split(Count, RecordList) end,
    {SplitRecords, []} = lists:mapfoldl(Fn, Acc, lists:reverse(Counts)),
    [Additional, Nameservers, Answers, Questions] = SplitRecords,
    {ok, {Questions, Answers, Nameservers, Additional}, Tail, State1}.


from_binary_edns(Msg = #{'Additional' := Additional, 'Return_code' := ReturnCode}) when length(Additional) =:= 0 ->
    Msg#{'Return_code' => return_code(ReturnCode)};
from_binary_edns(Msg = #{'Additional' := Additional0, 'Return_code' := RCode}) ->
    % Search for opt
    case lists:partition(fun ({_, Type, _, _, _}) -> Type =:= opt end, Additional0) of
        {[], _} -> Msg;
        {[{[], opt, Class, Ttl, Data}], Additional1} ->
            UDPSize = case dnsclass:from_to(Class, atom, value) of
                UDPSizeValue when UDPSizeValue < 512 -> 512;
                UDPSizeValue -> UDPSizeValue
            end,
            <<RCodeHigh, Version, DNSSecOK:1, _Z:15>> = <<Ttl:32>>,
            % Allow dnsopt key-value pairs to modify this map?
            % We could also just make maps:from_list and smush it to the current map...
            % Or smush the current map to that one.
            Map = case dnsopt:from_binary(Data) of
                {ok, TmpMap} -> TmpMap
            end,
            Msg#{
                'EDNS_version' => Version,
                'EDNS_dnssec_ok' => boolean(DNSSecOK),
                'EDNS_udp_payload_size' => UDPSize,
                'Return_code' => return_code((RCodeHigh bsl 4) bor RCode),
                'EDNS' => Map,
                'Additional' => Additional1
            };
        {_, Additional1} ->
            % Count towards message errors
            % Multiple OPTS should be considered a format_error...
            Msg#{'Additional' => Additional1}
    end.


from_binary_header(?HEADER) ->
    #{
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
    }.


-type from_binary_error_specific() ::
    {'invalid_resource_data', binary()} |
    'invalid_domain'                    |
    'truncated_domain'                  |
    'truncated_message'.
-type from_binary_error() ::
    'too_short'                                             | % Message wasn't long enough to represent DNS header
    {'format_error', from_binary_error_specific(), dnsmsg:message()}.% Otherwise valid, but contents were cut short
-spec from_binary(Bin :: binary() | [byte()]) ->
    {'ok', Msg :: dnslib:message(), TrailingBytes :: binary()} |
    {'error', from_binary_error()}. % Allow missing bytes and invalid_resources cases here
from_binary(Bin) ->
    from_binary(Bin, #{}).


from_binary(BinList, Opts) when is_list(BinList) ->
    from_binary(list_to_binary(BinList), Opts);
from_binary(MessageBin = <<BinHeader:4/binary,QuestionCount:16,AnswerCount:16,NameserverCount:16,AdditionalCount:16,BinData/binary>>, _Opts) ->
    Msg0 = from_binary_header(BinHeader),
    Counts = [QuestionCount, AnswerCount, NameserverCount, AdditionalCount],
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
            Msg2 = from_binary_edns(Msg1),
            case State of
                #bin_state{invalid_resources=0,invalid_questions=0} -> {ok, Msg2, Tail};
                #bin_state{invalid_resources=IQ,invalid_questions=IR} ->
                    {error, {format_error, {Msg1#{'Resource_errors' => IQ + IR}}}}
            end
    catch
        error:{truncated_message, State, Acc}                    -> from_binary_error_return(truncated_message, Counts, Acc, Msg0, State);
        error:{invalid_domain, Reason, State, Acc}               -> from_binary_error_return({invalid_domain, Reason}, Counts, Acc, Msg0, State);
        error:{truncated_domain, State, Acc}                     -> from_binary_error_return(truncated_domain, Counts, Acc, Msg0, State);
        error:{invalid_question_class, Type, Class, State, Acc}  -> from_binary_error_return({invalid_question_class, Type, Class}, Counts, Acc, Msg0, State);
        error:{truncated_resource_data, State, Acc}              -> from_binary_error_return(truncated_resource_data, Counts, Acc, Msg0, State);
        error:{invalid_resource_class, Type, Class, State, Acc}  -> from_binary_error_return({invalid_resource_class, Type, Class}, Counts, Acc, Msg0, State);
        error:{invalid_resource_data, Type, RData, State, Acc}   -> from_binary_error_return({invalid_resource_data, Type, RData}, Counts, Acc, Msg0, State)
    end;
from_binary(_, _) ->
    {error, too_short}.


from_binary_error_return(ErrSpec, Counts, Acc, Msg, State) ->
    {error, {format_error, ErrSpec, prepare_error_msg_return(Counts, Acc, Msg, State)}}.


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
to_bin_questions([{Domain0, Type, Class}|Rest], Acc, State0) ->
    {Domain1, State1=#bin_state{offset=Offset}} = compress_domain(Domain0, true, State0),
    Entry = <<Domain1/binary, (dnsrr:from_to(Type, atom, value)):16, (dnsclass:from_to(Class, atom, value)):16>>,
    to_bin_questions(Rest, [Entry|Acc], State1#bin_state{offset=Offset+4}).


to_bin_records([], Acc, State) ->
    {ok, lists:reverse(Acc), State};
to_bin_records([{Domain0, Type, Class, Ttl, Data}|Rest], Acc, State0) ->
    {Domain1, State1=#bin_state{offset=Offset0}} = compress_domain(Domain0, true, State0),
    case dnsrr:from_to(Type, atom, module) of
        Type when is_integer(Type), is_binary(Data) ->
            % To be compliant with RFC3597, we'll pass along records we don't understand.
            % We take it on faith that the resource does not contain domains compressions which
            % we'll mangle.
            BinLen = byte_size(Data),
            Entry = [<<Domain1/binary, Type:16, (dnsclass:from_to(Class, atom, value)):16, Ttl:32, BinLen:16>>, Data],
            to_bin_records(Rest, [Entry|Acc], State1#bin_state{offset=Offset0+10+BinLen});
        Module ->
            case
                case Module:to_binary(Data) of
                    {domains, CompressList} -> compress_datalist(CompressList, [], State1#bin_state{offset=Offset0+10});
                    {ok, Bin} ->
                        BinLen = iolist_size(Bin),
                        {Bin, BinLen, State1#bin_state{offset=Offset0+10+BinLen}}
                end
            of
                {RData, RDataLen, State2} ->
                    Entry = [<<Domain1/binary, (dnsrr:from_to(Module, module, value)):16, (dnsclass:from_to(Class, atom, value)):16, Ttl:32, RDataLen:16>>, RData],
                    to_bin_records(Rest, [Entry|Acc], State2)
            end
    end.


to_binary_edns(Msg = #{'EDNS' := Map, 'Additional' := Additional}, _) ->
    #{
        'EDNS_version' := Version,
        'EDNS_udp_payload_size' := MaxSize,
        'EDNS_dnssec_ok' := DNSSecOK,
        'Return_code' := ReturnCode0
    } = Msg,
    ReturnCode1 = return_code(ReturnCode0),
    % Had we other fields in the map (like DNS Cookie), we'd have to
    % product a list of those for the entry data
    <<Ttl:32>> = <<(ReturnCode1 bsr 4), Version, (boolean(DNSSecOK)):1, 0:15>>,
    {ok, Data} = dnsopt:to_binary(Map),
    Entry = {[], opt, MaxSize, Ttl, Data},
    Msg#{'Additional' => [Entry|Additional], 'Return_code' => ReturnCode1 band 16#0F};
to_binary_edns(Msg = #{'Return_code' := ReturnCode}, _) ->
    Msg#{'Return_code' => return_code(ReturnCode)}.


-spec to_binary(dns:message()) -> {'ok', Length :: 12..65535, Bin :: binary()}.
to_binary(Msg) ->
    to_binary(Msg, #{}).


-spec to_binary(dns:message(), Opts :: map()) -> {'ok', Length :: 12..65535, Bin :: binary()}.
to_binary(Msg, Opts) ->
    {ok, Len, IoList} = to_iolist(Msg, Opts),
    {ok, Len, iolist_to_binary(IoList)}.


-spec to_iolist(dns:message()) -> {'ok', Length :: 12..65535, Bin :: iolist()}.
to_iolist(Msg) ->
    to_iolist(Msg, #{}).


-spec to_iolist(dns:message(), Opts :: map()) -> {'ok', Length :: 12..65535, Bin :: iolist()}.
to_iolist(Msg0, Opts) ->
    % If a message at this point has non-applied interpret_results associated with it,
    % apply them.
    Msg1 = to_binary_edns(Msg0, Opts),
    case to_bin_header(Msg1) of
        {ok, Header} ->
            #{
                'Questions'   := Questions0,
                'Answers'     := Answers0,
                'Nameservers' := Nameservers0,
                'Additional'  := Additional0
            } = Msg1,
            QuestionCount = length(Questions0),
            AnswerCount = length(Answers0),
            NameserverCount = length(Nameservers0),
            AdditionalCount = length(Additional0),
            Counts = <<
                AnswerCount:16,
                NameserverCount:16,
                AdditionalCount:16
            >>,
            Questions1 = lists:reverse(Questions0),
            Answers1 = lists:reverse(Answers0),
            Nameservers1 = lists:reverse(Nameservers0),
            Additional1 = lists:reverse(Additional0),
            %% We could use a trie to store offsets for all available domains...
            {ok, Questions, State0} = to_bin_questions(Questions1, [], prep_to_bin_state(#bin_state{}, Opts)),
            {ok, Records, #bin_state{offset=Rlen}} = to_bin_records(lists:append([Answers1, Nameservers1, Additional1]), [], State0),
            {ok, Rlen, [Header, <<QuestionCount:16>>, Counts, Questions, Records]}
    end.


prep_to_bin_state(State = #bin_state{}, Opts = #{disable_compress := true}) ->
    prep_to_bin_state(State#bin_state{compress=false,compress_rdata=false}, maps:remove(disable_compress, Opts));
prep_to_bin_state(State, _) ->
    State.



to_bin_header(Msg) ->
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
        Reserved:1,
        (boolean(AuthData)):1,
        (boolean(CheckingDisabled)):1,
        ReturnCode:4
    >>}.


-spec indicate_domain(dnslib:domain()) -> {'domain', Compress :: false, dnslib:domain()}.
indicate_domain(Domain) ->
    {domain, false, Domain}.


-spec indicate_domain(dnslib:domain(), Offset :: non_neg_integer()) -> {'domain', dnslib:domain(), non_neg_integer()}.
indicate_domain(Domain, Offset) ->
    {domain, Domain, Offset}.


-spec indicate_domain_compress(dnslib:domain()) -> {'domain', Compress :: true, dnslib:domain()}.
indicate_domain_compress(Domain) ->
    {domain, true, Domain}.


-spec indicate_domain_decompress({'compressed', non_neg_integer(), [binary()]}, non_neg_integer()) -> {'compressed', non_neg_integer(), [binary()], non_neg_integer()}.
indicate_domain_decompress({compressed, Ref, Acc}, Offset) ->
    {compressed, Ref, Acc, Offset}.
