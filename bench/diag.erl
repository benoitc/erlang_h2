-module(diag).
-export([run/1]).

%% Open N raw TCP connections to the h2 server *simultaneously*, each sending
%% the client preface + SETTINGS + M HEADERS (GET /) in one burst, then read
%% all bytes for a short window. Report per-connection what came back.
%% Usage: erl ... -run diag run 8081 2 16   (port nconns nstreams)

run([PortS, NConnS, NStreamsS]) ->
    Port = list_to_integer(PortS),
    NConns = list_to_integer(NConnS),
    NStreams = list_to_integer(NStreamsS),
    Parent = self(),
    %% Pre-build each connection's outbound burst so the network sends happen
    %% as close together as possible across processes.
    Pids = [spawn(fun() -> conn(Parent, I, Port, NStreams) end)
            || I <- lists:seq(1, NConns)],
    Results = collect(length(Pids), []),
    io:format("~n==== RESULTS (~p conns x ~p streams) ====~n", [NConns, NStreams]),
    lists:foreach(fun({I, R}) -> io:format("conn ~p: ~p~n", [I, R]) end,
                  lists:keysort(1, Results)),
    halt(0).

conn(Parent, I, Port, NStreams) ->
    {ok, S} = gen_tcp:connect({127,0,0,1}, Port,
                              [binary, {active, false}, {packet, raw}, {nodelay, true}]),
    Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
    Settings = eh2_frame:encode(eh2_frame:settings([])),
    Ack = eh2_frame:encode(eh2_frame:settings_ack()),
    Ctx0 = eh2_hpack:new_context(4096),
    {Burst, _} = lists:foldl(
        fun(K, {Acc, Ctx}) ->
            Sid = 1 + 2*(K-1),
            Hdrs = [{<<":method">>, <<"GET">>},
                    {<<":path">>, <<"/">>},
                    {<<":scheme">>, <<"http">>},
                    {<<":authority">>, <<"127.0.0.1">>}],
            {HB, Ctx1} = eh2_hpack:encode(Hdrs, Ctx),
            Frame = eh2_frame:encode(eh2_frame:headers(Sid, HB, true)),
            {<<Acc/binary, Frame/binary>>, Ctx1}
        end, {<<>>, Ctx0}, lists:seq(1, NStreams)),
    ok = gen_tcp:send(S, <<Preface/binary, Settings/binary, Ack/binary, Burst/binary>>),
    Bytes = read_loop(S, <<>>, 0),
    {NHeaders, NData, NRst, NGoaway, Closed} = classify(Bytes),
    Parent ! {result, I, #{recv_bytes => byte_size(Bytes),
                           headers => NHeaders, data => NData,
                           rst => NRst, goaway => NGoaway, closed => Closed}}.

read_loop(S, Acc, Total) ->
    case gen_tcp:recv(S, 0, 300) of
        {ok, Data} -> read_loop(S, <<Acc/binary, Data/binary>>, Total + byte_size(Data));
        {error, timeout} -> Acc;
        {error, closed} -> Acc;
        {error, _} -> Acc
    end.

classify(Bin) -> classify(Bin, 0, 0, 0, 0).
classify(Bin, H, D, R, G) ->
    case eh2_frame:decode(Bin, 16384) of
        {ok, Frame, Rest} ->
            case element(1, Frame) of
                headers      -> classify(Rest, H+1, D, R, G);
                data         -> classify(Rest, H, D+1, R, G);
                rst_stream   -> classify(Rest, H, D, R+1, G);
                goaway       -> classify(Rest, H, D, R, G+1);
                _            -> classify(Rest, H, D, R, G)
            end;
        _ -> {H, D, R, G, no}
    end.

collect(0, Acc) -> Acc;
collect(N, Acc) ->
    receive {result, I, R} -> collect(N-1, [{I, R} | Acc]) end.
