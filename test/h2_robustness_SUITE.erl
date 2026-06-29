%% Regression tests for concurrency/robustness fixes:
%%  - pre_settings_ack_response: a client that pipelines a request before its
%%    SETTINGS-ACK (legal, RFC 9113 §3.4) must still get a response. Guards the
%%    bug where send_response/send_data were dropped while the server was still
%%    in the `settings` state.
%%  - sequential_no_stream_leak: many sequential client requests on one
%%    connection must not exhaust SETTINGS_MAX_CONCURRENT_STREAMS. Guards the
%%    bug where response HEADERS reset a half_closed_local stream back to `open`,
%%    so completed streams never reached `closed`.
-module(h2_robustness_SUITE).

-export([all/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).
-export([pre_settings_ack_response/1, sequential_no_stream_leak/1,
         respond_combined/1, respond_large_body_fallback/1]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

all() -> [pre_settings_ack_response, sequential_no_stream_leak,
          respond_combined, respond_large_body_fallback].

init_per_suite(Config) ->
    ok = application:ensure_started(crypto),
    {ok, _} = application:ensure_all_started(h2),
    Config.

end_per_suite(_Config) -> ok.

init_per_testcase(_TC, Config) ->
    process_flag(trap_exit, true),
    Handler = fun(Conn, StreamId, _M, _P, _H) ->
        h2:send_response(Conn, StreamId, 200,
                         [{<<"content-type">>, <<"text/plain">>}]),
        h2:send_data(Conn, StreamId, <<"Hello, World!">>, true)
    end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler}),
    [{server_ref, Ref}, {port, h2:server_port(Ref)} | Config].

end_per_testcase(_TC, Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        Ref -> h2:stop_server(Ref)
    end,
    ok.

%% Raw client: send preface + SETTINGS + a HEADERS request, pause so the server
%% dispatches the request while still awaiting our SETTINGS-ACK, then ACK.
pre_settings_ack_response(Config) ->
    Port = ?config(port, Config),
    {ok, S} = gen_tcp:connect({127,0,0,1}, Port,
                              [binary, {active, false}, {packet, raw}, {nodelay, true}]),
    Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
    Settings = eh2_frame:encode(eh2_frame:settings([])),
    ok = gen_tcp:send(S, <<Preface/binary, Settings/binary>>),
    Hdrs = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>},
            {<<":scheme">>, <<"http">>}, {<<":authority">>, <<"127.0.0.1">>}],
    {HB, _} = eh2_hpack:encode(Hdrs, eh2_hpack:new_context(4096)),
    ok = gen_tcp:send(S, eh2_frame:encode(eh2_frame:headers(1, HB, true))),
    timer:sleep(50),  %% ensure the server dispatches our request pre-ACK
    ok = gen_tcp:send(S, eh2_frame:encode(eh2_frame:settings_ack())),
    {Status, Body} = recv_response(S, <<>>, undefined, <<>>, erlang:monotonic_time(millisecond)),
    ?assertEqual(200, Status),
    ?assertEqual(<<"Hello, World!">>, Body),
    gen_tcp:close(S).

%% Collect frames until a DATA frame with END_STREAM closes stream 1.
recv_response(S, Buf, Status, Body, T0) ->
    case (erlang:monotonic_time(millisecond) - T0) > 4000 of
        true -> ct:fail({timeout, no_response, Status, Body});
        false ->
            case eh2_frame:decode(Buf, 16384) of
                {ok, {headers, 1, HB, _End, _EH}, Rest} ->
                    {ok, Decoded, _} = eh2_hpack:decode(HB, eh2_hpack:new_context(4096)),
                    St = binary_to_integer(proplists:get_value(<<":status">>, Decoded)),
                    recv_response(S, Rest, St, Body, T0);
                {ok, {data, 1, D, true, _}, _Rest} ->
                    {Status, <<Body/binary, D/binary>>};
                {ok, {data, 1, D, false, _}, Rest} ->
                    recv_response(S, Rest, Status, <<Body/binary, D/binary>>, T0);
                {ok, _Other, Rest} ->
                    recv_response(S, Rest, Status, Body, T0);
                _ ->
                    case gen_tcp:recv(S, 0, 1000) of
                        {ok, More} -> recv_response(S, <<Buf/binary, More/binary>>, Status, Body, T0);
                        {error, R} -> ct:fail({recv_error, R, Status, Body})
                    end
            end
    end.

%% 300 sequential requests > default max_concurrent_streams (100): before the
%% half-close fix this failed with max_streams_exceeded once leaked streams
%% filled the active count.
sequential_no_stream_leak(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    N = 300,
    Done = seq_loop(Conn, N, 0),
    ?assertEqual(N, Done),
    h2:close(Conn).

seq_loop(_Conn, N, Done) when Done >= N -> Done;
seq_loop(Conn, N, Done) ->
    {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>,
                           [{<<":authority">>, <<"127.0.0.1">>}]),
    ok = await(Conn, Sid),
    seq_loop(Conn, N, Done + 1).

await(Conn, Sid) ->
    receive
        {h2, Conn, {response, Sid, _St, _H}} -> await_body(Conn, Sid)
    after 4000 -> ct:fail({response_timeout, Sid})
    end.

await_body(Conn, Sid) ->
    receive
        {h2, Conn, {data, Sid, _D, true}} -> ok;
        {h2, Conn, {data, Sid, _D, false}} -> await_body(Conn, Sid)
    after 4000 -> ct:fail({body_timeout, Sid})
    end.

%% h2:respond/5 fast path: a normal small response must arrive intact.
respond_combined(Config) ->
    Body = <<"Hello, World!">>,
    {Status, Got} = respond_roundtrip(Config, Body),
    ?assertEqual(200, Status),
    ?assertEqual(Body, Got).

%% h2:respond/5 fallback: a body larger than SETTINGS_MAX_FRAME_SIZE cannot be
%% coalesced into one frame, so respond/5 falls back to the granular path. The
%% full body must still arrive intact across multiple DATA frames.
respond_large_body_fallback(Config) ->
    Body = binary:copy(<<"x">>, 100000),
    {Status, Got} = respond_roundtrip(Config, Body),
    ?assertEqual(200, Status),
    ?assertEqual(Body, Got).

respond_roundtrip(_Config, Body) ->
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:respond(Conn, Sid, 200,
                        [{<<"content-type">>, <<"text/plain">>}], Body)
    end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler}),
    Port = h2:server_port(Ref),
    try
        {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
        ok = h2:wait_connected(Conn),
        {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>,
                               [{<<":authority">>, <<"127.0.0.1">>}]),
        Status = receive
            {h2, Conn, {response, Sid, St, _H}} -> St
        after 4000 -> ct:fail(response_timeout)
        end,
        Got = collect_body(Conn, Sid, <<>>),
        h2:close(Conn),
        {Status, Got}
    after
        h2:stop_server(Ref)
    end.

collect_body(Conn, Sid, Acc) ->
    receive
        {h2, Conn, {data, Sid, D, true}}  -> <<Acc/binary, D/binary>>;
        {h2, Conn, {data, Sid, D, false}} -> collect_body(Conn, Sid, <<Acc/binary, D/binary>>)
    after 4000 -> ct:fail({body_timeout, Acc})
    end.
