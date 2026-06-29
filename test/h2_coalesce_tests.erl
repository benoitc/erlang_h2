%% @doc Socket-based tests for response-frame write coalescing.
%% Intactness: a large body must arrive byte-for-byte over h2c and TLS, via both
%% the granular (send_response + send_data) and respond/5 send paths.
%% Write count: a body that fits one flow-control window must leave the server in
%% a single DATA-bearing socket write that carries several DATA frames, proving
%% the frames are coalesced (one write, many frames) rather than one write each.
-module(h2_coalesce_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(BIG, 100 * 1024).

%% ---- intactness ----

granular_h2c_test_()  -> {timeout, 30, fun() -> roundtrip(tcp, granular) end}.
respond_h2c_test_()   -> {timeout, 30, fun() -> roundtrip(tcp, respond) end}.
granular_tls_test_()  -> {timeout, 30, fun() -> roundtrip(ssl, granular) end}.
respond_tls_test_()   -> {timeout, 30, fun() -> roundtrip(ssl, respond) end}.

roundtrip(Transport, Mode) ->
    {ok, _} = application:ensure_all_started(h2),
    Body = crypto:strong_rand_bytes(?BIG),
    Hdrs = [{<<"content-type">>, <<"application/octet-stream">>}],
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        case Mode of
            granular ->
                ok = h2:send_response(Conn, Sid, 200, Hdrs),
                ok = h2:send_data(Conn, Sid, Body, true);
            respond ->
                ok = h2:respond(Conn, Sid, 200, Hdrs, Body)
        end
    end,
    {Server, Port} = start_server(Transport, Handler),
    {ok, Client} = connect(Transport, Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, <<"GET">>, <<"/">>, [{<<"host">>, authority(Port)}]),
    Got = collect_body(Client, Sid, <<>>),
    ?assertEqual(byte_size(Body), byte_size(Got)),
    ?assertEqual(Body, Got),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---- write count (white-box, h2c) ----
%% A 50 KiB body fits the default 64 KiB window, so it drains in one batched
%% write of four 16 KiB-chunked DATA frames — no WINDOW_UPDATE round-trip, no
%% timing race. Before coalescing this was four separate writes.
coalesced_write_count_test_() ->
    {timeout, 30, fun write_count/0}.

write_count() ->
    {ok, _} = application:ensure_all_started(h2),
    TestPid = self(),
    Body = crypto:strong_rand_bytes(50 * 1024),
    Hdrs = [{<<"content-type">>, <<"application/octet-stream">>}],
    %% Hand the connection pid back and block until the test has armed tracing,
    %% so we capture the response writes rather than racing them.
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        TestPid ! {server_conn, Conn, self()},
        receive go -> ok after 5000 -> ok end,
        ok = h2:send_response(Conn, Sid, 200, Hdrs),
        ok = h2:send_data(Conn, Sid, Body, true)
    end,
    {Server, Port} = start_server(tcp, Handler),
    {ok, Client} = connect(tcp, Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, <<"GET">>, <<"/">>, [{<<"host">>, authority(Port)}]),
    {ServerConn, HandlerPid} =
        receive {server_conn, C, HP} -> {C, HP} after 5000 -> error(no_server_conn) end,
    1 = erlang:trace(ServerConn, true, [call]),
    erlang:trace_pattern({eh2_connection, sock_send, 2}, true, [local]),
    HandlerPid ! go,
    {Got, Writes} = collect_writes(Client, Sid, ServerConn, <<>>, []),
    erlang:trace(ServerConn, false, [call]),
    erlang:trace_pattern({eh2_connection, sock_send, 2}, false, [local]),
    ?assertEqual(Body, Got),
    DataWrites = [W || W <- Writes, count_data_frames(W) > 0],
    %% Exactly one DATA-bearing write...
    ?assertEqual(1, length(DataWrites)),
    %% ...carrying all four DATA frames (50 KiB / 16 KiB rounded up).
    ?assertEqual(4, count_data_frames(hd(DataWrites))),
    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---- helpers ----

start_server(tcp, Handler) ->
    {ok, Server} = h2:start_server(0, #{handler => Handler, transport => tcp}),
    {Server, h2:server_port(Server)};
start_server(ssl, Handler) ->
    {Cert, Key} = gen_certs(),
    {ok, Server} = h2:start_server(0, #{handler => Handler,
                                        cert => Cert, key => Key}),
    {Server, h2:server_port(Server)}.

connect(tcp, Port) ->
    h2:connect("127.0.0.1", Port, #{transport => tcp});
connect(ssl, Port) ->
    h2:connect("127.0.0.1", Port, #{transport => ssl, verify => verify_none}).

collect_body(Conn, Sid, Acc) ->
    receive
        {h2, Conn, {data, Sid, Data, true}}  -> <<Acc/binary, Data/binary>>;
        {h2, Conn, {data, Sid, Data, false}} -> collect_body(Conn, Sid, <<Acc/binary, Data/binary>>);
        {h2, Conn, _Other}                   -> collect_body(Conn, Sid, Acc)
    after 15000 ->
        error({timeout, byte_size(Acc)})
    end.

collect_writes(Conn, Sid, ServerConn, Body, Writes) ->
    receive
        {trace, ServerConn, call, {eh2_connection, sock_send, [_S, IoData]}} ->
            collect_writes(Conn, Sid, ServerConn, Body,
                           [iolist_to_binary(IoData) | Writes]);
        {h2, Conn, {data, Sid, Data, true}} ->
            %% Body complete; drain any trace messages still in flight.
            {<<Body/binary, Data/binary>>, drain_traces(ServerConn, Writes)};
        {h2, Conn, {data, Sid, Data, false}} ->
            collect_writes(Conn, Sid, ServerConn, <<Body/binary, Data/binary>>, Writes);
        {h2, Conn, _Other} ->
            collect_writes(Conn, Sid, ServerConn, Body, Writes)
    after 15000 ->
        error({timeout, byte_size(Body)})
    end.

drain_traces(ServerConn, Writes) ->
    receive
        {trace, ServerConn, call, {eh2_connection, sock_send, [_S, IoData]}} ->
            drain_traces(ServerConn, [iolist_to_binary(IoData) | Writes])
    after 300 ->
        Writes
    end.

%% Count DATA frames (type 0) inside one flattened socket write.
count_data_frames(Bin) ->
    length([t || {0, _Flags, _Payload} <- frames(Bin)]).

frames(<<>>) ->
    [];
frames(<<Len:24, Type:8, Flags:8, _R:1, _Sid:31, Payload:Len/binary, Rest/binary>>) ->
    [{Type, Flags, Payload} | frames(Rest)].

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

gen_certs() ->
    Dir = filename:join("/tmp", "h2_coalesce_" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Cert = filename:join(Dir, "cert.pem"),
    Key  = filename:join(Dir, "key.pem"),
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null", [Key, Cert]),
    _ = os:cmd(lists:flatten(Cmd)),
    {Cert, Key}.

-endif.
