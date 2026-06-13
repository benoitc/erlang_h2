%% @doc White-box frame "vectors" for the gRPC bidi flow-control and cancel
%% paths. Where h2_grpc_tests asserts observable behaviour, this module traces
%% h2_connection:sock_send/2 and decodes the exact frames on the wire, pinning:
%%   * manual flow control emits NO stream WINDOW_UPDATE until consume/3, then
%%     exactly one carrying the acked increment;
%%   * cancel/2 emits exactly one RST_STREAM with error code CANCEL (0x8);
%%   * a blocking send_data/5 writes NO DATA while the peer window is shut.
-module(h2_grpc_frame_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(WINDOW, 65535).
-define(TYPE_DATA, 0).
-define(TYPE_RST, 3).
-define(TYPE_WINDOW_UPDATE, 8).
%% RFC 7540 §7: CANCEL error code (mirrors ?CANCEL in include/h2.hrl).
-define(CANCEL, 16#8).

%% ---------------------------------------------------------------------------
%% Manual flow control: WINDOW_UPDATE gated on consume/3
%% ---------------------------------------------------------------------------

manual_window_update_vector_test_() ->
    {timeout, 30, fun manual_window_update_vector/0}.

manual_window_update_vector() ->
    Total = 100000,
    Body = crypto:strong_rand_bytes(Total),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200, []),
        ok = h2:send_data(Conn, Sid, Body, true)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, get_headers(Port),
                           #{handler => self(), flow_control => manual,
                             end_stream => true}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 5000 -> error(no_response) end,
    %% Pull the first window without consuming. Trace the client so we can prove
    %% no stream WINDOW_UPDATE went out for this stream while it stalled.
    trace_on(Client),
    {First, _} = drain_idle(Client, Sid, <<>>, 600),
    ?assert(byte_size(First) =< ?WINDOW),
    PreFrames = collect_frames(Client, 200),
    ?assertEqual([], [F || {?TYPE_WINDOW_UPDATE, _, S, _} = F <- PreFrames, S =:= Sid]),
    %% Now acknowledge consumption: exactly one stream WINDOW_UPDATE, increment
    %% equal to the acked byte count.
    Ack = byte_size(First),
    ok = h2:consume(Client, Sid, Ack),
    PostFrames = collect_frames(Client, 400),
    StreamWUs = [Inc || {?TYPE_WINDOW_UPDATE, _, S, <<_:1, Inc:31>>} <- PostFrames, S =:= Sid],
    ?assertEqual([Ack], StreamWUs),
    trace_off(Client),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% cancel/2 emits exactly one RST_STREAM(CANCEL)
%% ---------------------------------------------------------------------------

cancel_rst_vector_test_() ->
    {timeout, 30, fun cancel_rst_vector/0}.

cancel_rst_vector() ->
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        ok = h2:send_response(Conn, Sid, 200, []),
        timer:sleep(1000)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, post_headers(Port),
                           #{handler => self(), end_stream => false}),
    receive {h2, Client, {response, Sid, 200, _}} -> ok
    after 5000 -> error(no_response) end,
    trace_on(Client),
    ok = h2:cancel(Client, Sid),
    Frames = collect_frames(Client, 400),
    Rsts = [Code || {?TYPE_RST, _, S, <<Code:32>>} <- Frames, S =:= Sid],
    ?assertEqual([?CANCEL], Rsts),
    trace_off(Client),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---------------------------------------------------------------------------
%% Blocking send_data/5 writes no DATA while the window is shut
%% ---------------------------------------------------------------------------

blocking_send_no_data_vector_test_() ->
    {timeout, 30, fun blocking_send_no_data_vector/0}.

blocking_send_no_data_vector() ->
    Test = self(),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        Test ! {server_conn, Conn, Sid, self()},
        receive go -> ok after 5000 -> ok end,
        ok = h2:send_response(Conn, Sid, 200, []),
        %% Fill exactly one window, then attempt a blocking send into the shut
        %% window. It must park (no DATA on the wire) and time out.
        ok = h2:send_data(Conn, Sid, crypto:strong_rand_bytes(?WINDOW), false),
        Test ! window_filled,
        R = h2:send_data(Conn, Sid, <<"blocked">>, false, #{block => 300}),
        Test ! {send_result, R},
        timer:sleep(500)
    end,
    {Server, Port} = start_server(Handler),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, get_headers(Port),
                           #{handler => self(), flow_control => manual,
                             end_stream => true}),
    {ServerConn, Sid, HandlerPid} =
        receive {server_conn, C, S, HP} -> {C, S, HP} after 5000 -> error(no_server_conn) end,
    HandlerPid ! go,
    %% Let the first window flush, then start tracing for the blocking-send phase.
    receive window_filled -> ok after 5000 -> error(no_fill) end,
    _ = drain_idle(Client, Sid, <<>>, 300),
    trace_on(ServerConn),
    ?assertEqual({error, timeout},
                 receive {send_result, R} -> R after 5000 -> error(no_send_result) end),
    Frames = collect_frames(ServerConn, 200),
    ?assertEqual([], [F || {?TYPE_DATA, _, S, _} = F <- Frames, S =:= Sid]),
    trace_off(ServerConn),
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

get_headers(Port) ->
    [{<<":method">>, <<"GET">>}, {<<":scheme">>, <<"http">>},
     {<<":path">>, <<"/download">>}, {<<":authority">>, authority(Port)}].

post_headers(Port) ->
    [{<<":method">>, <<"POST">>}, {<<":scheme">>, <<"http">>},
     {<<":path">>, <<"/svc/Bidi">>}, {<<":authority">>, authority(Port)},
     {<<"content-type">>, <<"application/grpc">>}].

trace_on(Conn) ->
    1 = erlang:trace(Conn, true, [call]),
    erlang:trace_pattern({h2_connection, sock_send, 2}, true, [local]),
    ok.

trace_off(Conn) ->
    erlang:trace(Conn, false, [call]),
    erlang:trace_pattern({h2_connection, sock_send, 2}, false, [local]),
    ok.

%% Collect traced socket writes for IdleMs of quiet, decode them into frames.
collect_frames(Conn, IdleMs) ->
    Bins = collect_writes(Conn, IdleMs, []),
    lists:flatmap(fun frames/1, Bins).

collect_writes(Conn, IdleMs, Acc) ->
    receive
        {trace, Conn, call, {h2_connection, sock_send, [_S, IoData]}} ->
            collect_writes(Conn, IdleMs, [iolist_to_binary(IoData) | Acc])
    after IdleMs ->
        lists:reverse(Acc)
    end.

drain_idle(Conn, Sid, Acc, IdleMs) ->
    receive
        {h2, Conn, {data, Sid, Data, true}}  -> {<<Acc/binary, Data/binary>>, true};
        {h2, Conn, {data, Sid, Data, false}} -> drain_idle(Conn, Sid, <<Acc/binary, Data/binary>>, IdleMs);
        {h2, Conn, _Other}                   -> drain_idle(Conn, Sid, Acc, IdleMs)
    after IdleMs ->
        {Acc, false}
    end.

%% Decode a flattened socket write into {Type, Flags, StreamId, Payload} frames.
frames(<<>>) ->
    [];
frames(<<Len:24, Type:8, Flags:8, _R:1, Sid:31, Payload:Len/binary, Rest/binary>>) ->
    [{Type, Flags, Sid, Payload} | frames(Rest)];
frames(_Partial) ->
    [].

-endif.
