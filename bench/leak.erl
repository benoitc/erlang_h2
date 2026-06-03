-module(leak).
-export([run/1]).

%% Verify completed client streams don't leak as active. Do N sequential GETs on
%% one client connection; before the Phase 1b fix this hit max_streams_exceeded
%% after ~peer_max_concurrent_streams (100) completed requests.
%% Usage: -run leak run <n>

run([NS]) ->
    N = list_to_integer(NS),
    {ok, _} = application:ensure_all_started(h2),
    Body = <<"Hello, World!">>,
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        h2:send_response(Conn, Sid, 200, [{<<"content-type">>, <<"text/plain">>}]),
        h2:send_data(Conn, Sid, Body, true)
    end,
    {ok, Srv} = h2:start_server(0, #{transport => tcp, handler => Handler}),
    Port = h2:server_port(Srv),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    Result = loop(Conn, N, 0),
    io:format("requested=~p succeeded=~p~n", [N, Result]),
    case Result of
        N -> io:format("PASS: no stream leak~n");
        _ -> io:format("FAIL: stalled/errored after ~p~n", [Result])
    end,
    halt(0).

loop(_Conn, N, Done) when Done >= N -> Done;
loop(Conn, N, Done) ->
    case h2:request(Conn, <<"GET">>, <<"/">>,
                    [{<<":authority">>, <<"127.0.0.1">>}]) of
        {ok, Sid} ->
            case await(Conn, Sid) of
                ok -> loop(Conn, N, Done + 1);
                _  -> Done
            end;
        {error, _R} ->
            Done
    end.

await(Conn, Sid) ->
    receive
        {h2, Conn, {response, Sid, _Status, _H}} -> await_body(Conn, Sid);
        {h2, Conn, {stream_reset, Sid, _}} -> error;
        {h2, Conn, {closed, _}} -> error
    after 5000 -> timeout
    end.

await_body(Conn, Sid) ->
    receive
        {h2, Conn, {data, Sid, _Data, true}} -> ok;
        {h2, Conn, {data, Sid, _Data, false}} -> await_body(Conn, Sid);
        {h2, Conn, {trailers, Sid, _}} -> ok
    after 5000 -> timeout
    end.
