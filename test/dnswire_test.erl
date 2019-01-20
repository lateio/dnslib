-module(dnswire_test).
-include_lib("eunit/include/eunit.hrl").

dnswire_from_binary_error_test() ->
    {ok, _, <<>>} = dnswire:from_binary(<<0:(12*8)>>),
    {ok, _, <<0>>} = dnswire:from_binary(<<0:(13*8)>>),
    {error, {format_error, truncated_message, _}} = dnswire:from_binary(<<0:32, 1:16, 0:48>>),
    {error, {format_error, truncated_message, _}} = dnswire:from_binary(<<0:32, 0:16, 1:16, 0:32>>).


encode_test() ->
    Result1 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        2:16, % Question count
        2:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        3, "arv", 2, "io", 0, 1:16, 1:16,
        3, "arv", 2, "io", 0, 2:16, 1:16,
        3, "arv", 2, "io", 0, 1:16, 1:16, 60:32, 4:16, 0:32,
        3, "arv", 2, "io", 0, 2:16, 1:16, 60:32, 8:16, 3, "arv", 2, "io", 0
    >>,
    Question1 = dnslib:question("arv.io", a, in),
    Question2 = dnslib:question("arv.io", ns, in),
    Resource1 = dnslib:resource("arv.io", a, in, 60, {0,0,0,0}),
    Resource2 = dnslib:resource("arv.io", ns, in, 60, "arv.io"),
    {ok, 84, Result1} = dnswire:to_binary(dnsmsg:new(#{id => 0}, [Question1, Question2], [Resource1, Resource2]), [{edns, false}, {domain_compression, false}]),
    Msg0 = dnsmsg:new(#{id => 0}),
    Msg1 = dnsmsg:add_question(Msg0, Question1),
    Msg2 = dnsmsg:add_question(Msg1, Question2),
    Msg3 = dnsmsg:add_answer(Msg2, Resource1),
    Msg4 = dnsmsg:add_answer(Msg3, Resource2),
    {ok, 84, Result1} = dnswire:to_binary(Msg4, [{edns, false}, {domain_compression, false}]),
    Msg0_1 = dnsmsg:set_section(Msg0, question, [Question1, Question2]),
    Msg0_2 = dnsmsg:set_section(Msg0_1, answer, [Resource1, Resource2]),
    {ok, 84, Result1} = dnswire:to_binary(Msg0_2, [{edns, false}, {domain_compression, false}]),
    Result2 = <<
        16#FFFF:16, % ID
        1:1,  % Is response
        16#F:4,  % Opcode
        1:1,  % Authoritative
        1:1,  % Truncated
        1:1,  % Recursion desired
        1:1,  % Recursion available
        0:1,  % Reserved
        1:1,  % Authorized data
        1:1,  % Checking disabled
        16#F:4,  % Return code
        0:16, % Question count
        0:16, % Answer count
        0:16, % Authority count
        0:16 % Additional count
    >>,
    Opts = #{
        id => 16#FFFF,
        is_response => true,
        opcode => 16#F,
        return_code => 16#F,
        authoritative => true,
        truncated => true,
        recursion_desired => true,
        recursion_available => true,
        authenticated_data => true,
        checking_disabled => true
    },
    {ok, _, Result2} = dnswire:to_binary(dnsmsg:new(Opts), [{edns, false}]).


domain_compression_unknown_resource_test() ->
    Bin1 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        2:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        3, "arv", 2, "io", 0, 400:16, 1:16, 60:32, 17:16, 8, "compress", 3, "arv", 2, "io", 0,
        3:2, 30:14, 2:16, 1:16, 60:32, 8:16, 3, "arv", 2, "io", 0
    >>,
    Resource1 = dnslib:resource("arv.io", 400, in, 60, <<8, "compress", 3, "arv", 2, "io", 0>>),
    Resource2 = dnslib:resource("compress.arv.io", ns, in, 60, "arv.io"),
    Msg1 = dnsmsg:new(#{id => 0, edns => false}, [], [Resource1, Resource2]),
    {ok, Msg1, <<>>} = dnswire:from_binary(Bin1).


dnswire_data_domains_test() ->
    Resource1 = dnslib:resource("arv.io", ns, in, 60, "ns1.arv.io"),
    Resource2 = dnslib:resource("arv.io", mx, in, 60, "0 smtp.arv.io"),
    Msg = dnsmsg:new(#{}, [], [Resource1, Resource2]),
    {ok, _, Bin} = dnswire:to_binary(Msg),
    {ok, Msg, _} = dnswire:from_binary(Bin).


forward_compression_test() ->
    Bin1 = <<
        0:32, % Header
        0:16, % Question count
        2:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        3, "arv", 2, "io", 3:2, 12:14, 1:16, 1:16, 60:32, 4:16, 0:32,
        3, "arv", 2, "io", 3:2, 12:14, 2:16, 1:16, 60:32, 8:16, 3, "arv", 2, "io", 0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin1),
    Bin2 = <<
        0:32, % Header
        0:16, % Question count
        2:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        3:2, 12:14, 1:16, 1:16, 60:32, 4:16, 0:32,
        3, "arv", 2, "io", 3:2, 12:14, 2:16, 1:16, 60:32, 8:16, 3, "arv", 2, "io", 0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin2).


dnswire_encode_decode_test() ->
    %Msg1 = dnsmsg:add_question(dnsmsg:new(), {[], ns, in}),
    Msg1 = dnsmsg:new(),
    {ok, _, Bin1} = dnswire:to_binary(Msg1),
    {ok, Msg2, <<>>} = dnswire:from_binary(Bin1),
    {ok, _, Bin1} = dnswire:to_binary(Msg2).


dnswire_resource_order_test() ->
    Question1 = {[<<"arv">>,<<"io">>], a, in},
    Question2 = {[<<"sub">>,<<"arv">>,<<"io">>], a, in},
    Resource1 = {[<<"arv">>,<<"io">>], a, in, 0, {0,0,0,0}},
    Resource2 = {[<<"sub">>,<<"arv">>,<<"io">>], a, in, 0, {0,0,0,0}},
    Msg = dnsmsg:new(#{}, [Question1, Question2], [Resource1, Resource2], [Resource1, Resource2], [Resource1, Resource2]),
    {ok, _, Bin} = dnswire:to_binary(Msg),
    {ok, Msg, <<>>} = dnswire:from_binary(Bin).
    % Need to hand-craft a binary and test with that, too.


dnswire_encode_max_length_test() ->
    Msg = dnsmsg:new(#{id => 0}, [{[], a, in}, {[], ns, in}]),
    Msg1 = dnsmsg:new(#{id => 0}, [{[], a, in}, {[], ns, in}], {[], a, in, 0, {0,0,0,0}}),
    {ok, 22, _} = dnswire:to_binary(Msg, [{max_length, 22}, {edns, false}]),
    {ok, 33, _} = dnswire:to_binary(Msg, [{max_length, 33}, {edns, true}]),
    {ok, 37, _} = dnswire:to_binary(Msg1, [{max_length, 37}, {edns, false}]),
    {ok, 48, _} = dnswire:to_binary(Msg1, [{max_length, 48}, {edns, true}]),
    ResBin1 = <<0:22, 1:1, 0:9, 0:64>>,
    {partial, 12, ResBin1, {[{[], a, in}, {[], ns, in}], [], [], []}} = dnswire:to_binary(Msg, [{max_length, 12}, {edns, false}]),
    ResBin2 = <<0:22, 0:1, 0:9, 0:64>>,
    {partial, 12, ResBin2, {[{[], a, in}, {[], ns, in}], [], [], []}} = dnswire:to_binary(Msg, [{max_length, 12}, {edns, false}, {truncate, false}]),
    ResBin3 = <<0:22, 1:1, 0:9, 2:16, 0:16, 0:32, 0, 1:16, 1:16, 0, 2:16, 1:16>>,
    ResBin4 = <<0:22, 0:1, 0:9, 2:16, 0:16, 0:32, 0, 1:16, 1:16, 0, 2:16, 1:16>>,
    {partial, 22, ResBin3, {[], [{[], a, in, 0, {0,0,0,0}}], [], []}} = dnswire:to_binary(Msg1, [{max_length, 22}, {edns, false}]),
    {partial, 22, ResBin4, {[], [{[], a, in, 0, {0,0,0,0}}], [], []}} = dnswire:to_binary(Msg1, [{max_length, 22}, {edns, false}, {truncate, false}]),
    {partial, 22, ResBin3, {[], [{[], a, in, 0, {0,0,0,0}}], [], []}} = dnswire:to_binary(Msg1, [{max_length, 27}, {edns, false}]),
    {partial, 22, ResBin4, {[], [{[], a, in, 0, {0,0,0,0}}], [], []}} = dnswire:to_binary(Msg1, [{max_length, 27}, {edns, false}, {truncate, false}]),
    Msg2 = dnsmsg:new(#{id => 0}, [{[], a, in}, {[], ns, in}], [{[], a, in, 0, {1,1,1,1}}, {[], a, in, 0, {2,2,2,2}}], {[], a, in, 0, {3,3,3,3}}, {[], a, in, 0, {4,4,4,4}}),
    ResBin5 = <<0:22, 1:1, 0:9, 2:16, 1:16, 0:32, 0, 1:16, 1:16, 0, 2:16, 1:16, 0, 1:16, 1:16, 0:32, 4:16, 1, 1, 1, 1>>,
    ResBin6 = <<0:22, 0:1, 0:9, 2:16, 1:16, 0:32, 0, 1:16, 1:16, 0, 2:16, 1:16, 0, 1:16, 1:16, 0:32, 4:16, 1, 1, 1, 1>>,
    {partial, _, ResBin5, {[], [{[], a, in, 0, {2,2,2,2}}], [{[], a, in, 0, {3,3,3,3}}], [{[], a, in, 0, {4,4,4,4}}]}} = dnswire:to_binary(Msg2, [{max_length, 38}, {edns, false}]),
    {partial, _, ResBin6, {[], [{[], a, in, 0, {2,2,2,2}}], [{[], a, in, 0, {3,3,3,3}}], [{[], a, in, 0, {4,4,4,4}}]}} = dnswire:to_binary(Msg2, [{max_length, 38}, {edns, false}, {truncate, false}]),
    ResBin7 = <<
        0:22, 1:1, 0:9, 2:16, 2:16, 0:32, 0, 1:16, 1:16, 0, 2:16, 1:16,
        0, 1:16, 1:16, 0:32, 4:16, 1, 1, 1, 1,
        0, 1:16, 1:16, 0:32, 4:16, 2, 2, 2, 2
    >>,
    {partial, _, ResBin7, {[], [], [{[], a, in, 0, {3,3,3,3}}], [{[], a, in, 0, {4,4,4,4}}]}} = dnswire:to_binary(Msg2, [{max_length, 53}, {edns, false}]),
    ResBin8 = <<
        0:22, 1:1, 0:9, 2:16, 2:16, 1:16, 0:16, 0, 1:16, 1:16, 0, 2:16, 1:16,
        0, 1:16, 1:16, 0:32, 4:16, 1, 1, 1, 1,
        0, 1:16, 1:16, 0:32, 4:16, 2, 2, 2, 2,
        0, 1:16, 1:16, 0:32, 4:16, 3, 3, 3, 3
    >>,
    {partial, _, ResBin8, {[], [], [], [{[], a, in, 0, {4,4,4,4}}]}} = dnswire:to_binary(Msg2, [{max_length, 68}, {edns, false}]),
    ResBin9 = <<
        0:22, 0:1, 0:9, 2:16, 2:16, 1:16, 1:16, 0, 1:16, 1:16, 0, 2:16, 1:16,
        0, 1:16, 1:16, 0:32, 4:16, 1, 1, 1, 1,
        0, 1:16, 1:16, 0:32, 4:16, 2, 2, 2, 2,
        0, 1:16, 1:16, 0:32, 4:16, 3, 3, 3, 3,
        0, 1:16, 1:16, 0:32, 4:16, 4, 4, 4, 4
    >>,
    {ok, _, ResBin9} = dnswire:to_binary(Msg2, [{max_length, 83}, {edns, false}]).


format_errors1_test() ->
    % Domain decompression produces an overly long domain
    MaxDomain = lists:append([<<"a">>|[<<"long">> || _ <- lists:seq(1,49)]], [<<"domain">>]),
    {ok, MaxDomainBin} = dnslib:domain_to_binary(MaxDomain),
    <<MaxDomainStart:254/binary, _/bits>> = MaxDomainBin,
    Bin1 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        2:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        3, "arv", 2, "io", 0, 400:16, 1:16, 60:32, 17:16, 8, "compress", 3, "arv", 2, "io", 0,
        MaxDomainStart/binary, 3:2, 12:14, 2:16, 1:16, 60:32, 8:16, 3, "arv", 2, "io", 0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin1),
    %
    %% Test max domain
    Bin2 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        1:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        MaxDomainBin/binary, 400:16, 1:16, 60:32, 17:16, 8, "compress", 3, "arv", 2, "io", 0
    >>,
    {ok, _, <<>>} = dnswire:from_binary(Bin2),
    %
    %% Test max domain plus one byte
    Bin3 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        1:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        MaxDomainStart/binary, 2, "io", 0, 400:16, 1:16, 60:32, 17:16, 8, "compress", 3, "arv", 2, "io", 0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin3).

format_errors2_test() ->
    % Truncated messages
    Bin1 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        2:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        0, 400:16, 1:16, 60:32, 17:16, 8, "compress", 3, "arv", 2, "io", 0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin1),
    Bin2 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        1:16, % Question count
        0:16, % Answer count
        0:16, % Authority count
        0:16 % Additional count
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin2),
    Bin3 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        1:16, % Question count
        0:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        0, 400:16, 1:16, 60:32, 17:16, 8, "compress", 3, "arv", 2, "io", 0
    >>,
    {ok, _, <<60:32, 17:16, 8, "compress", 3, "arv", 2, "io", 0>>} = dnswire:from_binary(Bin3).

format_errors3_test() ->
    % Truncated messages
    Bin1 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        1:16, % Question count
        0:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin1),
    {error, {format_error, _, _}} = dnswire:from_binary(<<Bin1/binary, 1:16>>),
    {ok, _, <<>>} = dnswire:from_binary(<<Bin1/binary, 1:16, 1:16>>),
    Bin2 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        1:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin1),
    {error, {format_error, _, _}} = dnswire:from_binary(<<Bin1/binary, 1:16>>),
    {ok, _, <<>>} = dnswire:from_binary(<<Bin1/binary, 1:16, 1:16>>),
    {error, {format_error, _, _}} = dnswire:from_binary(<<Bin2/binary, 1:16, 1:16, 60:32>>),
    {error, {format_error, _, _}} = dnswire:from_binary(<<Bin2/binary, 1:16, 1:16, 60:32, 0>>),
    {error, {format_error, _, _}} = dnswire:from_binary(<<Bin2/binary, 1:16, 1:16, 60:32, 0, 4>>),
    {error, {format_error, _, _}} = dnswire:from_binary(<<Bin2/binary, 1:16, 1:16, 60:32, 0, 4, 0>>),
    {error, {format_error, _, _}} = dnswire:from_binary(<<Bin2/binary, 1:16, 1:16, 60:32, 0, 4, 0, 0>>),
    {error, {format_error, _, _}} = dnswire:from_binary(<<Bin2/binary, 1:16, 1:16, 60:32, 0, 4, 0, 0, 0>>),
    {ok, _, <<>>} = dnswire:from_binary(<<Bin2/binary, 1:16, 1:16, 60:32, 0, 4, 0, 0, 0, 0>>).

format_errors4_test() ->
    % Multiple opt records
    Bin1 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        0:16, % Answer count
        0:16, % Authority count
        2:16, % Additional count
        0, 41:16, 512:16, 0, 0, 0, 0, 0:16,
        0, 41:16, 512:16, 0, 0, 0, 0, 0:16
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin1).

format_errors5_test() ->
    % AAAA record with an invalid class
    Bin1 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        1:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        0, 28:16, 2:16, 0, 0, 0, 0, 4:16, 0,0,0,0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin1).

format_errors6_test() ->
    % Try to use a QTYPE in a resource
    Bin1 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        1:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        0, 28:16, 2:16, 0, 0, 0, 0, 4:16, 0,0,0,0
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin1),
    %
    %% Opt not in additional
    Bin2 = <<
        0:16, % ID
        0:1,  % Is response
        0:4,  % Opcode
        0:1,  % Authoritative
        0:1,  % Truncated
        0:1,  % Recursion desired
        0:1,  % Recursion available
        0:1,  % Reserved
        0:1,  % Authorized data
        0:1,  % Checking disabled
        0:4,  % Return code
        0:16, % Question count
        1:16, % Answer count
        0:16, % Authority count
        0:16, % Additional count
        0, 41:16, 512:16, 0, 0, 0, 0, 0:16
    >>,
    {error, {format_error, _, _}} = dnswire:from_binary(Bin2).
