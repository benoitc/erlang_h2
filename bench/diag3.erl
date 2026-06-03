-module(diag3).
-export([run/1]).

%% Windowed, sustained, full-duplex h2 client that mimics h2load:
%% keep Window streams in flight, open a new stream each time one finishes,
%% until Total responses received per connection. Run NConns concurrently.
%% Usage: -run diag2 run <port> <nconns> <window> <total>

run([PortS, NConnS, WinS, TotalS]) ->
    Port = list_to_integer(PortS),
    NConns = list_to_integer(NConnS),
    Win = list_to_integer(WinS),
    Total = list_to_integer(TotalS),
    Parent = self(),
    _ = [spawn(fun() -> conn(Parent, I, Port, Win, Total) end)
         || I <- lists:seq(1, NConns)],
    Results = collect(NConns, []),
    io:format("~n==== diag2 (~p conns, win=~p, total=~p each) ====~n",
              [NConns, Win, Total]),
    lists:foreach(fun({I, R}) -> io:format("conn ~p: ~p~n", [I, R]) end,
                  lists:keysort(1, Results)),
    halt(0).

conn(Parent, I, Port, Win, Total) ->
    {ok, S} = gen_tcp:connect({127,0,0,1}, Port,
                              [binary, {active, false}, {packet, raw}, {nodelay, true}]),
    Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
    Settings = h2_frame:encode(h2_frame:settings([])),
    ok = gen_tcp:send(S, <<Preface/binary, Settings/binary>>),
    Ctx = h2_hpack:new_context(4096),
    %% Open initial window of streams (ids 1,3,5,...)
    Initial = min(Win, Total),
    {Ctx1, NextId} = send_n(S, 1, Initial, Ctx),
    timer:sleep(20),  %% let server dispatch our requests while still in `settings`
    ok = gen_tcp:send(S, h2_frame:encode(h2_frame:settings_ack())),
    Sent = Initial,
    Res = (catch loop(S, <<>>, Ctx1, NextId, Sent, 0, Total, Win)),
    Parent ! {result, I, Res}.

%% loop: Buffer, Ctx, NextId, Sent, Done, Total, Win
loop(_S, _Buf, _Ctx, _NextId, _Sent, Done, Total, _Win) when Done >= Total ->
    #{done => Done, status => ok};
loop(S, Buf, Ctx, NextId, Sent, Done, Total, Win) ->
    case gen_tcp:recv(S, 0, 5000) of
        {ok, Data} ->
            Buf1 = <<Buf/binary, Data/binary>>,
            {Completed, Goaway, Rst, Rest} = drain(Buf1, 0, false, 0),
            case Goaway of
                false -> ok;
                _ -> ok
            end,
            case Goaway of
                G when G =/= false ->
                    #{done => Done + Completed, status => {got_goaway, G}, rst => Rst};
                false ->
                    Done1 = Done + Completed,
                    %% For each completed stream, open a new one (windowed)
                    ToSend = min(Completed, Total - Sent),
                    {Ctx1, NextId1} = send_n(S, NextId, ToSend, Ctx),
                    loop(S, Rest, Ctx1, NextId1, Sent + ToSend, Done1, Total, Win)
            end;
        {error, closed} ->
            #{done => Done, status => peer_closed, sent => Sent};
        {error, timeout} ->
            #{done => Done, status => stalled_timeout, sent => Sent};
        {error, R} ->
            #{done => Done, status => {error, R}, sent => Sent}
    end.

%% Decode all complete frames in Buf; count DATA-with-endstream as completions.
drain(Buf, Completed, Goaway, Rst) ->
    case h2_frame:decode(Buf, 16384) of
        {ok, Frame, Rest} ->
            case Frame of
                {data, _Sid, _D, true, _Sz}    -> drain(Rest, Completed+1, Goaway, Rst);
                {data, _Sid, _D, false, _Sz}   -> drain(Rest, Completed, Goaway, Rst);
                {headers, _Sid, _HB, true, _E} -> drain(Rest, Completed+1, Goaway, Rst);
                {goaway, Last, Code, _}        -> drain(Rest, Completed, {Last, Code}, Rst);
                {rst_stream, _Sid, _Code}      -> drain(Rest, Completed, Goaway, Rst+1);
                _                              -> drain(Rest, Completed, Goaway, Rst)
            end;
        {more, _} -> {Completed, Goaway, Rst, Buf};
        {error, _} -> {Completed, Goaway, Rst, Buf};
        {error, _, Rest} -> {Completed, Goaway, Rst, Rest}
    end.

send_n(_S, NextId, 0, Ctx) -> {Ctx, NextId};
send_n(S, NextId, N, Ctx) ->
    Hdrs = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>},
            {<<":scheme">>, <<"http">>}, {<<":authority">>, <<"127.0.0.1">>}],
    {HB, Ctx1} = h2_hpack:encode(Hdrs, Ctx),
    Frame = h2_frame:encode(h2_frame:headers(NextId, HB, true)),
    ok = gen_tcp:send(S, Frame),
    send_n(S, NextId + 2, N - 1, Ctx1).

collect(0, Acc) -> Acc;
collect(N, Acc) -> receive {result, I, R} -> collect(N-1, [{I, R} | Acc]) end.
