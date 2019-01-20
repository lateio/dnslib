-module(doc_test).
-include_lib("eunit/include/eunit.hrl").

index_test() ->
    % Request
    Question = dnslib:question("arv.io", a, in),
    Request0 = dnsmsg:new(#{}, Question),
    {ok, ReqBinLen, ReqBin} = dnswire:to_binary(Request0),
    ReqBinLen = byte_size(ReqBin),
    {ok, Request0, <<>>} = dnswire:from_binary(ReqBin),

    % Response
    Answer = dnslib:resource("arv.io IN 60 A 127.0.0.1"),
    Request1 = dnsmsg:add_response_answer(Request0, Answer),
    Response = dnsmsg:response(Request1),
    {ok, ResBinLen, ResIolist} = dnswire:to_iolist(Response),
    ResBin = iolist_to_binary(ResIolist),
    ResBinLen = byte_size(ResBin),
    {ok, Response, <<"Trailing">>} = dnswire:from_binary(<<ResBin/binary, "Trailing">>),

    % Make sense of the response
    {ok, [{Question, ok, [Answer]}]} = dnsmsg:interpret_response(Response),

    % Keep the answer safe...
    Path = filename:join(["test", "sample_files", "treasures"]),
    ok = dnsfile:write_resources(Path, [Answer]),

    % ...But but take a good look at it now and then
    {ok, [Answer]} = dnsfile:consult(Path).


max_domain_test() ->
    Domain = [<<"a">> || _ <- lists:seq(1,127)],
    true = dnslib:is_valid_domain(Domain).
