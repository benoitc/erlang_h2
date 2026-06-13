%% @doc gRPC bidirectional-streaming contract tests over h2 (h2c loopback).
%%
%% Covers the gRPC bidi contract: interleaved DATA both ways on one stream,
%% client half-close + server trailers, per-stream event routing to a handler,
%% receive-side backpressure (consume/3), send-side backpressure (blocking
%% send_data/5 and the non-blocking send_buffer_full cap), mid-stream cancel
%% from each side, GOAWAY/closed delivered to the stream handler, and ownership
%% (a dying call process must not take down the connection or sibling streams).
-module(h2_grpc_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(WINDOW, 65535).

%% ---------------------------------------------------------------------------
%% Acceptance: N interleaved messages each way, half-close, trailers (item 1-3)
%% ---------------------------------------------------------------------------

bidi_roundtrip_test_() ->
    {timeout, 30, fun bidi_roundtrip/0}.

bidi_roundtrip() ->
    N = 5,
    %% Server: register a per-stream handler, stream N messages out while
    %% reading the client's N messages, then close with grpc-status trailers.
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:set_stream_handler(Conn, Sid, self()),
        ok = h2:send_response(Conn, Sid, 200,
                              [{<<"content-type">>, <<"application/grpc">>}]),
        [ok = h2:send_data(Conn, Sid, srv_msg(I), false) || I <- lists:seq(1, N)],
        N = recv_until_fin(Conn, Sid, 0),
        ok = h2:send_trailers(Conn, Sid, [{<<"grpc-status">>, <<"0">>}])
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, grpc_headers(Port),
                           #{handler => self(), end_stream => false}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 5000 -> error(no_response) end,
    %% Client streams N messages, half-closing on the last DATA.
    [ok = h2:send_data(Client, Sid, cli_msg(I), I =:= N) || I <- lists:seq(1, N)],
    %% Client keeps receiving after half-close: N server messages + trailers.
    {Msgs, Trailers} = collect_until_trailers(Client, Sid, [], 5000),
    ?assertEqual([srv_msg(I) || I <- lists:seq(1, N)], Msgs),
    ?assertEqual(<<"0">>, proplists:get_value(<<"grpc-status">>, Trailers)),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% Late handler registration: buffered events replay in order (item 1)
%% ---------------------------------------------------------------------------

late_handler_replay_test_() ->
    {timeout, 30, fun late_handler_replay/0}.

late_handler_replay() ->
    %% Unary server response (headers + data + trailers) sent immediately.
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200,
                              [{<<"content-type">>, <<"application/grpc">>}]),
        ok = h2:send_data(Conn, Sid, <<"payload">>, false),
        ok = h2:send_trailers(Conn, Sid, [{<<"grpc-status">>, <<"0">>}])
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    %% defer => true: events buffer instead of going to the owner (test proc).
    {ok, Sid} = h2:request(Client, grpc_headers(Port),
                           #{defer => true, end_stream => true}),
    %% Let response + data + trailers all arrive and buffer before we register.
    timer:sleep(300),
    %% A separate collector pid proves events route to the handler, not the owner.
    Test = self(),
    Collector = spawn(fun() -> collect_events(Test, Client, Sid) end),
    ok = h2:set_stream_handler(Client, Sid, Collector),
    Events = receive {events, Es} -> Es after 5000 -> error(no_events) end,
    ?assertMatch([{response, Sid, 200, _},
                  {data, Sid, <<"payload">>, _},
                  {trailers, Sid, _} | _], Events),
    %% Owner (test process) must have received none of the stream events.
    ?assertEqual(no_owner_event, owner_leak(Client, Sid)),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% Receive-side backpressure: manual window gates the peer (item 4)
%% ---------------------------------------------------------------------------

slow_consumer_backpressure_test_() ->
    {timeout, 30, fun slow_consumer_backpressure/0}.

slow_consumer_backpressure() ->
    Total = 100000,
    Body = crypto:strong_rand_bytes(Total),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200, []),
        ok = h2:send_data(Conn, Sid, Body, true)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, grpc_get_headers(Port),
                           #{handler => self(), flow_control => manual,
                             end_stream => true}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 5000 -> error(no_response) end,
    %% Without consuming, the stream window (one initial window) bounds how much
    %% the server can push: it must stall before the full body arrives.
    {First, _Fin1} = drain_idle(Client, Sid, <<>>, 600),
    ?assert(byte_size(First) =< ?WINDOW),
    ?assert(byte_size(First) < Total),
    %% Acknowledge consumption: the window reopens and the rest flows.
    Rest = consume_loop(Client, Sid, First),
    ?assertEqual(Body, Rest),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% Send-side backpressure (item 5)
%% ---------------------------------------------------------------------------

%% Non-blocking: once the window is exhausted, an oversized send is rejected
%% with send_buffer_full rather than buffered without bound.
send_window_nonblocking_test_() ->
    {timeout, 30, fun send_window_nonblocking/0}.

send_window_nonblocking() ->
    Test = self(),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200, []),
        %% Fill exactly one window, then attempt a >1MB send.
        ok = h2:send_data(Conn, Sid, crypto:strong_rand_bytes(?WINDOW), false),
        R = h2:send_data(Conn, Sid, crypto:strong_rand_bytes(2 * 1024 * 1024), false),
        Test ! {send_result, R},
        timer:sleep(1000)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    %% Client never consumes, so the server's stream send window stays shut.
    {ok, _Sid} = h2:request(Client, grpc_get_headers(Port),
                            #{handler => spawn(fun idle/0), flow_control => manual,
                              end_stream => true}),
    R = receive {send_result, X} -> X after 5000 -> error(no_send_result) end,
    ?assertEqual({error, send_buffer_full}, R),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% Blocking: send_data/5 with #{block => T} returns {error, timeout} when the
%% window never opens, and ok once consume/3 reopens it.
send_window_blocking_test_() ->
    {timeout, 30, fun send_window_blocking/0}.

send_window_blocking() ->
    Test = self(),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200, []),
        ok = h2:send_data(Conn, Sid, crypto:strong_rand_bytes(?WINDOW), false),
        %% Window is shut: this must time out.
        T1 = h2:send_data(Conn, Sid, <<"blocked">>, false, #{block => 300}),
        Test ! {timed_out, T1},
        %% This one blocks until the test consumes, then succeeds.
        T2 = h2:send_data(Conn, Sid, <<"unblocked">>, false, #{block => 5000}),
        Test ! {unblocked, T2},
        timer:sleep(500)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, grpc_get_headers(Port),
                           #{handler => self(), flow_control => manual,
                             end_stream => true}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 5000 -> error(no_response) end,
    ?assertEqual({error, timeout},
                 receive {timed_out, R1} -> R1 after 5000 -> error(no_timeout) end),
    %% Reopen the window; the parked blocking send completes.
    ok = h2:consume(Client, Sid, ?WINDOW),
    ?assertEqual(ok,
                 receive {unblocked, R2} -> R2 after 5000 -> error(no_unblock) end),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% Mid-stream cancel from each side, delivered to the peer's handler (item 6)
%% ---------------------------------------------------------------------------

cancel_from_client_test_() ->
    {timeout, 30, fun cancel_from_client/0}.

cancel_from_client() ->
    Test = self(),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:set_stream_handler(Conn, Sid, self()),
        ok = h2:send_response(Conn, Sid, 200, []),
        receive
            {h2, Conn, {stream_reset, Sid, Code}} -> Test ! {server_reset, Code}
        after 5000 -> Test ! {server_reset, timeout}
        end
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, grpc_headers(Port),
                           #{handler => self(), end_stream => false}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 5000 -> error(no_response) end,
    ok = h2:cancel(Client, Sid),
    ?assertEqual(cancel,
                 receive {server_reset, C} -> C after 5000 -> error(no_reset) end),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

cancel_from_server_test_() ->
    {timeout, 30, fun cancel_from_server/0}.

cancel_from_server() ->
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200, []),
        ok = h2:cancel(Conn, Sid),
        timer:sleep(500)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, grpc_headers(Port),
                           #{handler => self(), end_stream => false}),
    %% The client's stream handler (test proc) must observe the reset.
    Code = receive
        {h2, Client, {stream_reset, Sid, C}} -> C
    after 5000 -> error(no_reset) end,
    ?assertEqual(cancel, Code),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% GOAWAY and closed delivered to the stream handler (item 6)
%% ---------------------------------------------------------------------------

goaway_and_closed_to_handler_test_() ->
    {timeout, 30, fun goaway_and_closed_to_handler/0}.

goaway_and_closed_to_handler() ->
    %% We tear the connection down on purpose; the client conn is linked to us.
    process_flag(trap_exit, true),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200, []),
        timer:sleep(200),
        ok = h2:goaway(Conn),
        timer:sleep(1000)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    %% A dedicated handler pid (not the owner) must learn of goaway + closed.
    Test = self(),
    HandlerPid = spawn(fun() -> teardown_collector(Test, Client) end),
    {ok, _Sid} = h2:request(Client, grpc_headers(Port),
                            #{handler => HandlerPid, end_stream => false}),
    ?assertEqual(got_goaway,
                 receive {teardown, goaway} -> got_goaway
                 after 5000 -> error(no_goaway) end),
    ?assertEqual(got_closed,
                 receive {teardown, closed} -> got_closed
                 after 5000 -> error(no_closed) end),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% Ownership: a dying call process leaves the connection and siblings intact
%% (item 7)
%% ---------------------------------------------------------------------------

ownership_isolation_test_() ->
    {timeout, 30, fun ownership_isolation/0}.

ownership_isolation() ->
    process_flag(trap_exit, true),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200, []),
        ok = h2:send_data(Conn, Sid, <<"ok">>, true)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    %% Stream A owned by a short-lived call process that we kill mid-flight.
    Test = self(),
    CallProc = spawn(fun() ->
        {ok, SidA} = h2:request(Client, grpc_headers(Port),
                                #{handler => self(), end_stream => false}),
        Test ! {stream_a, SidA},
        receive die -> exit(killed) end
    end),
    SidA = receive {stream_a, S} -> S after 5000 -> error(no_stream_a) end,
    %% Kill the owning call process — connection must survive.
    CallProc ! die,
    timer:sleep(200),
    ?assert(is_process_alive(Client)),
    %% A sibling stream still works end to end.
    {ok, SidB} = h2:request(Client, grpc_get_headers(Port), #{handler => self()}),
    receive {h2, Client, {response, SidB, 200, _}} -> ok
    after 5000 -> error(sibling_no_response) end,
    Body = collect_body(Client, SidB, <<>>),
    ?assertEqual(<<"ok">>, Body),
    %% The connection never required controlling_process for any of this.
    ?assert(is_process_alive(Client)),
    _ = SidA,
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% Stress: small window + small frame size forces fragmentation + refills
%% ---------------------------------------------------------------------------

small_window_bidi_test_() ->
    {timeout, 60, fun small_window_bidi/0}.

small_window_bidi() ->
    %% Tiny window on both sides: every 8 KiB message is sent in ~2 KiB slices
    %% with a WINDOW_UPDATE refill between them, in both directions, exercising
    %% the chunking + flush paths under the new dispatch code (auto flow control).
    Settings = #{initial_window_size => 2048, max_frame_size => 16384},
    {Server, Port} = start_server_with(echo_fun(), Settings),
    {ok, Client} = connect_with(Port, Settings),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, grpc_headers(Port),
                           #{handler => self(), end_stream => false}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 5000 -> error(no_response) end,
    Msgs = [crypto:strong_rand_bytes(8192) || _ <- lists:seq(1, 5)],
    Got = echo_exchange(Client, Sid, Msgs, 30000),
    ?assertEqual(iolist_to_binary(Msgs), Got),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% Stress: many concurrent multiplexed bidi streams on one connection
%% ---------------------------------------------------------------------------

concurrent_streams_test_() ->
    {timeout, 60, fun concurrent_streams/0}.

concurrent_streams() ->
    K = 20,
    {Server, Port} = start_server(echo_fun()),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    Test = self(),
    %% Each call runs in its own process owning only its stream's events.
    _Workers = [spawn(fun() -> concurrent_worker(Test, Client, Port, I) end)
                || I <- lists:seq(1, K)],
    Results = [receive {worker_done, I, R} -> {I, R}
               after 20000 -> error({worker_timeout, I}) end
               || I <- lists:seq(1, K)],
    [?assertEqual({I, ok}, lists:keyfind(I, 1, Results)) || I <- lists:seq(1, K)],
    ?assert(is_process_alive(Client)),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

concurrent_worker(Test, Client, Port, I) ->
    Msg = <<"stream-", (integer_to_binary(I))/binary>>,
    {ok, Sid} = h2:request(Client, grpc_headers(Port),
                           #{handler => self(), end_stream => false}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 10000 -> exit(no_response) end,
    Got = echo_exchange(Client, Sid, [Msg], 10000),
    R = case Got of Msg -> ok; Other -> {mismatch, Other} end,
    Test ! {worker_done, I, R}.

%% ---------------------------------------------------------------------------
%% Stress: high message count one way then the other (ordering / leak)
%% ---------------------------------------------------------------------------

high_message_count_test_() ->
    {timeout, 60, fun high_message_count/0}.

high_message_count() ->
    N = 10000,
    {Server, Port} = start_server(echo_fun()),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, grpc_headers(Port),
                           #{handler => self(), end_stream => false}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 5000 -> error(no_response) end,
    Msgs = [<<(integer_to_binary(I))/binary, $;>> || I <- lists:seq(1, N)],
    Got = echo_exchange(Client, Sid, Msgs, 30000),
    %% Exact concatenation equality proves all N arrived in order, none lost.
    ?assertEqual(iolist_to_binary(Msgs), Got),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ===========================================================================
%% Helpers
%% ===========================================================================

start_server(Handler) ->
    {ok, _} = application:ensure_all_started(h2),
    {ok, Server} = h2:start_server(0, #{handler => Handler, transport => tcp}),
    {Server, h2:server_port(Server)}.

connect(Port) ->
    h2:connect("127.0.0.1", Port, #{transport => tcp}).

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

grpc_headers(Port) ->
    [{<<":method">>, <<"POST">>},
     {<<":scheme">>, <<"http">>},
     {<<":path">>, <<"/svc.Service/Bidi">>},
     {<<":authority">>, authority(Port)},
     {<<"content-type">>, <<"application/grpc">>},
     {<<"te">>, <<"trailers">>}].

grpc_get_headers(Port) ->
    [{<<":method">>, <<"GET">>},
     {<<":scheme">>, <<"http">>},
     {<<":path">>, <<"/download">>},
     {<<":authority">>, authority(Port)}].

cli_msg(I) -> <<"client-", (integer_to_binary(I))/binary>>.
srv_msg(I) -> <<"server-", (integer_to_binary(I))/binary>>.

%% Server-side: count inbound DATA frames until END_STREAM.
recv_until_fin(Conn, Sid, Count) ->
    receive
        {h2, Conn, {data, Sid, _Data, true}}  -> Count + 1;
        {h2, Conn, {data, Sid, _Data, false}} -> recv_until_fin(Conn, Sid, Count + 1)
    after 5000 ->
        error({recv_until_fin_timeout, Count})
    end.

%% Client-side: collect DATA payloads until the trailers arrive.
collect_until_trailers(Conn, Sid, Acc, Timeout) ->
    receive
        {h2, Conn, {data, Sid, <<>>, true}}   -> collect_until_trailers(Conn, Sid, Acc, Timeout);
        {h2, Conn, {data, Sid, Data, _Fin}}   -> collect_until_trailers(Conn, Sid, [Data | Acc], Timeout);
        {h2, Conn, {trailers, Sid, Trailers}} -> {lists:reverse(Acc), Trailers}
    after Timeout ->
        error({collect_until_trailers_timeout, lists:reverse(Acc)})
    end.

collect_body(Conn, Sid, Acc) ->
    receive
        {h2, Conn, {data, Sid, Data, true}}  -> <<Acc/binary, Data/binary>>;
        {h2, Conn, {data, Sid, Data, false}} -> collect_body(Conn, Sid, <<Acc/binary, Data/binary>>);
        {h2, Conn, {trailers, Sid, _}}       -> Acc
    after 5000 ->
        error({collect_body_timeout, Acc})
    end.

%% Collect the first few replayed events for a stream and report them back.
collect_events(Test, Conn, Sid) ->
    collect_events(Test, Conn, Sid, []).

collect_events(Test, _Conn, _Sid, Acc) when length(Acc) >= 3 ->
    Test ! {events, lists:reverse(Acc)};
collect_events(Test, Conn, Sid, Acc) ->
    receive
        {h2, Conn, {response, Sid, _, _} = E}  -> collect_events(Test, Conn, Sid, [E | Acc]);
        {h2, Conn, {data, Sid, _, _} = E}      -> collect_events(Test, Conn, Sid, [E | Acc]);
        {h2, Conn, {trailers, Sid, _} = E}     -> collect_events(Test, Conn, Sid, [E | Acc]);
        {h2, Conn, _Other}                     -> collect_events(Test, Conn, Sid, Acc)
    after 5000 ->
        Test ! {events, lists:reverse(Acc)}
    end.

%% Assert the owner (test process) received no stream-scoped events for Sid.
owner_leak(Conn, Sid) ->
    receive
        {h2, Conn, {response, Sid, _, _}} -> {leak, response};
        {h2, Conn, {data, Sid, _, _}}     -> {leak, data};
        {h2, Conn, {trailers, Sid, _}}    -> {leak, trailers}
    after 200 ->
        no_owner_event
    end.

%% Drain DATA until the stream goes idle for IdleMs (proving a stall).
drain_idle(Conn, Sid, Acc, IdleMs) ->
    receive
        {h2, Conn, {data, Sid, Data, true}}  -> {<<Acc/binary, Data/binary>>, true};
        {h2, Conn, {data, Sid, Data, false}} -> drain_idle(Conn, Sid, <<Acc/binary, Data/binary>>, IdleMs)
    after IdleMs ->
        {Acc, false}
    end.

%% Repeatedly consume what we have and pull the next window until END_STREAM.
consume_loop(Conn, Sid, Acc) ->
    ok = h2:consume(Conn, Sid, byte_size(Acc)),
    case drain_idle(Conn, Sid, <<>>, 800) of
        {Chunk, true}  -> <<Acc/binary, Chunk/binary>>;
        {<<>>, false}  -> error({stalled, byte_size(Acc)});
        {Chunk, false} -> consume_loop(Conn, Sid, <<Acc/binary, Chunk/binary>>)
    end.

teardown_collector(Test, Conn) ->
    receive
        {h2, Conn, {goaway, _, _}} -> Test ! {teardown, goaway}, teardown_collector(Test, Conn);
        {h2, Conn, {closed, _}}    -> Test ! {teardown, closed};
        {h2, Conn, _}              -> teardown_collector(Test, Conn)
    after 8000 ->
        ok
    end.

idle() ->
    receive _ -> idle() end.

%% A protobuf-agnostic gRPC echo handler: mirror the inbound DATA byte stream
%% back out, end with grpc-status: 0 trailers.
echo_fun() ->
    fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:set_stream_handler(Conn, Sid, self()),
        ok = h2:send_response(Conn, Sid, 200,
                              [{<<"content-type">>, <<"application/grpc">>}]),
        echo_loop(Conn, Sid)
    end.

echo_loop(Conn, Sid) ->
    receive
        {h2, Conn, {data, Sid, <<>>, true}} ->
            ok = h2:send_trailers(Conn, Sid, [{<<"grpc-status">>, <<"0">>}]);
        {h2, Conn, {data, Sid, Bytes, true}} ->
            ok = h2:send_data(Conn, Sid, Bytes, false),
            ok = h2:send_trailers(Conn, Sid, [{<<"grpc-status">>, <<"0">>}]);
        {h2, Conn, {data, Sid, Bytes, false}} ->
            ok = h2:send_data(Conn, Sid, Bytes, false),
            echo_loop(Conn, Sid);
        {h2, Conn, _Other} ->
            echo_loop(Conn, Sid)
    after 30000 ->
        ok
    end.

%% Send all messages (half-closing on the last) and collect the echoed bytes.
echo_exchange(Client, Sid, Msgs, Timeout) ->
    send_msgs(Client, Sid, Msgs),
    {Got, _Trailers} = collect_until_trailers(Client, Sid, [], Timeout),
    iolist_to_binary(Got).

send_msgs(Client, Sid, [Last]) ->
    ok = h2:send_data(Client, Sid, Last, true);
send_msgs(Client, Sid, [M | Rest]) ->
    ok = h2:send_data(Client, Sid, M, false),
    send_msgs(Client, Sid, Rest).

start_server_with(Handler, Settings) ->
    {ok, _} = application:ensure_all_started(h2),
    {ok, Server} = h2:start_server(0, #{handler => Handler, transport => tcp,
                                        settings => Settings}),
    {Server, h2:server_port(Server)}.

connect_with(Port, Settings) ->
    h2:connect("127.0.0.1", Port, #{transport => tcp, settings => Settings}).

-endif.
