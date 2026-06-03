-module(prof).
-export([run/1]).

%% In-node profiler: start the h2 server, drive N windowed requests over one
%% raw connection, fprof-trace the whole thing, dump own-time hotspots.
%% Usage: -run prof run <total> <window>

run([TotalS, WinS]) ->
    Total = list_to_integer(TotalS),
    Win = list_to_integer(WinS),
    {ok, _} = application:ensure_all_started(h2),
    Body = <<"Hello, World!">>,
    Hdrs = [{<<"content-type">>, <<"text/plain">>}],
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        h2:send_response(Conn, Sid, 200, Hdrs),
        h2:send_data(Conn, Sid, Body, true)
    end,
    {ok, Srv} = h2:start_server(0, #{transport => tcp, handler => Handler}),
    Port = h2:server_port(Srv),
    %% open + handshake (optimistic ACK so we reach `connected`)
    {ok, S} = gen_tcp:connect({127,0,0,1}, Port,
                              [binary, {active, false}, {packet, raw}, {nodelay, true}]),
    Pre = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
    Set = h2_frame:encode(h2_frame:settings([])),
    Ack = h2_frame:encode(h2_frame:settings_ack()),
    ok = gen_tcp:send(S, <<Pre/binary, Set/binary, Ack/binary>>),
    Ctx = h2_hpack:new_context(4096),
    %% warm up (not traced)
    drive(S, Ctx, Win, min(Win, 2000)),
    %% traced run
    fprof:trace([start, {procs, all}]),
    drive(S, Ctx, Win, Total),
    fprof:trace(stop),
    io:format("profiling ~p requests done; analysing...~n", [Total]),
    fprof:profile(),
    fprof:analyse([{dest, "/tmp/fprof.analysis"}, {sort, own}, {totals, true}]),
    io:format("analysis written~n"),
    halt(0).

drive(S, Ctx0, Win, Total) ->
    {Ctx1, Next} = send_n(S, 1, min(Win, Total), Ctx0),
    loop(S, <<>>, Ctx1, Next, min(Win, Total), 0, Total, Win).

loop(_S, _B, _C, _N, _Sent, Done, Total, _W) when Done >= Total -> ok;
loop(S, B, C, N, Sent, Done, Total, W) ->
    case gen_tcp:recv(S, 0, 5000) of
        {ok, Data} ->
            B1 = <<B/binary, Data/binary>>,
            {Comp, Rest} = drain(B1, 0),
            ToSend = min(Comp, Total - Sent),
            {C1, N1} = send_n(S, N, ToSend, C),
            loop(S, Rest, C1, N1, Sent + ToSend, Done + Comp, Total, W);
        _ -> ok
    end.

drain(B, C) ->
    case h2_frame:decode(B, 16384) of
        {ok, {data, _, _, true, _}, R} -> drain(R, C+1);
        {ok, _F, R} -> drain(R, C);
        _ -> {C, B}
    end.

send_n(_S, N, 0, C) -> {C, N};
send_n(S, N, K, C) ->
    H = [{<<":method">>,<<"GET">>},{<<":path">>,<<"/">>},
         {<<":scheme">>,<<"http">>},{<<":authority">>,<<"127.0.0.1">>}],
    {HB, C1} = h2_hpack:encode(H, C),
    ok = gen_tcp:send(S, h2_frame:encode(h2_frame:headers(N, HB, true))),
    send_n(S, N+2, K-1, C1).
