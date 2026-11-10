%% @doc When the peer goes away, the owner and stream handlers must learn it
%% promptly. Two paths delayed {closed, _} by about 5 s:
%%
%% - On a server TLS socket, ssl:close/1 waits up to 5 s for a silent peer to
%%   close TCP, and terminate/3 closed before notifying.
%% - A connection that had sent GOAWAY for a connection error dropped bytes
%%   the peer sent afterwards without asking the socket for more, so the
%%   peer's close was never seen until the 5 s close timer fired.
-module(h2_tls_close_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
%% Well under the 5 s close timer.
-define(BOUND, 500).

close_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"TLS: handler told promptly when the server sees ssl_closed first",
       {timeout, 30, fun() -> peer_closes(ssl) end}},
      {"TCP: handler told promptly when the server sees tcp_closed first",
       {timeout, 30, fun() -> peer_closes(gen_tcp) end}},
      {"TLS: handler told promptly when GOAWAY stops the owner first",
       {timeout, 30, fun() -> goaway_owner_exit_first(ssl) end}},
      {"TCP: handler told promptly when GOAWAY stops the owner first",
       {timeout, 30, fun() -> goaway_owner_exit_first(gen_tcp) end}},
      {"TLS: peer close seen after a connection error and more data",
       {timeout, 30, fun() -> close_after_connection_error(ssl) end}},
      {"TCP: peer close seen after a connection error and more data",
       {timeout, 30, fun() -> close_after_connection_error(gen_tcp) end}},
      {"client close returns promptly when the server keeps its socket",
       {timeout, 30, fun client_close/0}}]}.

%% The peer closes its socket without a GOAWAY.
peer_closes(T) ->
    {Ref, Relay, Sock, Conn} = server_with_stream(T),
    try
        T0 = now_ms(),
        ok = T:close(Sock),
        assert_closed_within(Conn, T0)
    after
        stop_relay(Relay),
        h2:stop_server(Ref)
    end.

%% The peer sends GOAWAY and keeps TCP open. The server owner loop returns on
%% the GOAWAY, so the connection stops through its owner's exit while the peer
%% is still there. The relay passes the GOAWAY, then forwards nothing more
%% with both sockets open.
goaway_owner_exit_first(T) ->
    {Ref, Relay, Sock, Conn} = server_with_stream(T),
    try
        freeze_after_next(Relay),
        MRef = monitor(process, Conn),
        T0 = now_ms(),
        ok = T:send(Sock, h2_frame:encode(h2_frame:goaway(1, no_error, <<>>))),
        assert_closed_within(Conn, T0),
        %% The connection itself is gone too, not stuck closing the socket.
        receive {'DOWN', MRef, process, Conn, _} -> ok after ?BOUND -> error(conn_alive) end
    after
        stop_relay(Relay),
        _ = T:close(Sock),
        h2:stop_server(Ref)
    end.

%% WINDOW_UPDATE with a zero increment on stream 0 is a connection error
%% (RFC 9113 §6.9): the server sends GOAWAY, half-closes and waits for the
%% peer to close. The relay drops what the server sends, so the peer has not
%% seen the GOAWAY when, once the server is closing, it sends one more frame
%% and then closes; the server must still see the close.
close_after_connection_error(T) ->
    {Ref, Relay, Sock, Conn} = server_with_stream(T),
    try
        hold_down(Relay),
        ok = T:send(Sock, <<4:24, 8:8, 0:8, 0:1, 0:31, 0:32>>),
        ok = wait_state(Conn, closing, 100),
        ok = T:send(Sock, h2_frame:encode(h2_frame:ping(<<0:64>>))),
        timer:sleep(50),
        T0 = now_ms(),
        ok = T:close(Sock),
        assert_closed_within(Conn, T0)
    after
        stop_relay(Relay),
        h2:stop_server(Ref)
    end.

%% A raw TLS server that completes the h2 handshake, behind a relay that then
%% forwards nothing more with both sockets open, so the client's close is
%% never answered. OTP's ssl only waits for the peer in the server role, so
%% this guards the client side rather than reproducing a stall.
client_close() ->
    #{server := {Cert, Key}} = certs(),
    {ok, LSock} = ssl:listen(0, [binary, {active, false}, {reuseaddr, true},
                                 {certfile, Cert}, {keyfile, Key},
                                 {alpn_preferred_protocols, [<<"h2">>]}]),
    {ok, {_, Port}} = ssl:sockname(LSock),
    Self = self(),
    Peer = spawn_link(fun() ->
                              {ok, TS} = ssl:transport_accept(LSock, 5000),
                              {ok, S} = ssl:handshake(TS, 5000),
                              ok = ssl:send(S, [h2_frame:encode(h2_frame:settings([])),
                                                h2_frame:encode(h2_frame:settings_ack())]),
                              Self ! peer_ready,
                              receive stop -> ssl:close(S) end
                      end),
    {Relay, RelayPort} = relay(Port),
    try
        {ok, Conn} = h2:connect("localhost", RelayPort,
                                #{ssl_opts => [{verify, verify_none}]}),
        receive peer_ready -> ok after 5000 -> error(no_peer) end,
        freeze(Relay),
        T0 = now_ms(),
        ok = h2:close(Conn),
        ?assert(now_ms() - T0 < ?BOUND),
        receive {h2, Conn, {closed, _}} -> ok
        after 1000 -> error(no_closed)
        end
    after
        stop_relay(Relay),
        Peer ! stop,
        ssl:close(LSock)
    end.

%% ---------------------------------------------------------------------------

%% A server whose handler makes the test process the request stream's handler
%% and answers nothing; a raw client, through a relay, opens one stream on it.
server_with_stream(T) ->
    Self = self(),
    Handler = fun(Conn, StreamId, _M, _P, _H) ->
                      ok = h2:set_stream_handler(Conn, StreamId, Self),
                      Self ! {registered, Conn}
              end,
    {ok, Ref} = start_server(T, Handler),
    {Relay, RelayPort} = relay(h2:server_port(Ref)),
    {ok, Sock} = connect(T, RelayPort),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>},
               {<<":scheme">>, <<"https">>}, {<<":authority">>, <<"localhost">>}],
    {Block, _} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    ok = T:send(Sock, [?PREFACE,
                       h2_frame:encode(h2_frame:settings([])),
                       h2_frame:encode(h2_frame:settings_ack()),
                       h2_frame:encode(h2_frame:headers(1, Block, false))]),
    Conn = receive {registered, C} -> C after 5000 -> error(no_request) end,
    {Ref, Relay, Sock, Conn}.

start_server(ssl, Handler) ->
    #{server := {Cert, Key}} = certs(),
    h2:start_server(0, #{cert => Cert, key => Key, handler => Handler});
start_server(gen_tcp, Handler) ->
    h2:start_server(0, #{transport => tcp, handler => Handler}).

connect(ssl, Port) ->
    ssl:connect("localhost", Port, [binary, {active, false}, {verify, verify_none},
                                    {alpn_advertised_protocols, [<<"h2">>]}], 5000);
connect(gen_tcp, Port) ->
    gen_tcp:connect("localhost", Port, [binary, {active, false}], 5000).

%% A TCP relay to Port. Once frozen it forwards nothing more but keeps both
%% sockets open, like a peer that has gone silent. In hold mode it keeps
%% forwarding client-to-server but drops what the server sends.
relay(Port) ->
    {ok, L} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true}]),
    {ok, LPort} = inet:port(L),
    Pid = spawn(fun() ->
                        {ok, A} = gen_tcp:accept(L, 5000),
                        %% exit_on_close false: the server's half-close
                        %% must not close this end on its own.
                        {ok, B} = gen_tcp:connect("localhost", Port,
                                                  [binary, {active, false},
                                                   {exit_on_close, false}], 5000),
                        ok = inet:setopts(A, [{active, true}]),
                        ok = inet:setopts(B, [{active, true}]),
                        relay_loop(A, B, forward)
                end),
    ok = gen_tcp:controlling_process(L, Pid),
    {Pid, LPort}.

relay_loop(A, B, Mode) ->
    receive
        {tcp, A, Data} when Mode =/= frozen ->
            _ = gen_tcp:send(B, Data),
            relay_loop(A, B, case Mode of once -> frozen; _ -> Mode end);
        {tcp, B, _Data} when Mode =:= hold ->
            relay_loop(A, B, Mode);
        {tcp_closed, B} when Mode =:= hold ->
            %% The server's half-close: keep the client side open.
            relay_loop(A, B, Mode);
        {tcp, B, Data} when Mode =/= frozen ->
            _ = gen_tcp:send(A, Data),
            relay_loop(A, B, Mode);
        {tcp_closed, A} when Mode =/= frozen ->
            _ = gen_tcp:close(B),
            relay_loop(A, B, Mode);
        {tcp_closed, B} when Mode =/= frozen ->
            _ = gen_tcp:close(A),
            relay_loop(A, B, Mode);
        {freeze, From} ->
            From ! {frozen, self()},
            relay_loop(A, B, frozen);
        {freeze_after_next, From} ->
            From ! {frozen, self()},
            relay_loop(A, B, once);
        {hold_down, From} ->
            From ! {frozen, self()},
            relay_loop(A, B, hold);
        stop ->
            ok;
        _ ->
            relay_loop(A, B, Mode)
    end.

freeze(Relay) -> relay_call(Relay, freeze).

%% Forward the next client-to-server chunk, then freeze.
freeze_after_next(Relay) -> relay_call(Relay, freeze_after_next).

relay_call(Relay, Msg) ->
    Relay ! {Msg, self()},
    receive {frozen, Relay} -> ok after 5000 -> error(relay) end.

wait_state(Conn, Name, 0) ->
    error({not_in_state, Name, sys:get_state(Conn)});
wait_state(Conn, Name, N) ->
    case sys:get_state(Conn) of
        {Name, _} -> ok;
        _ -> timer:sleep(10), wait_state(Conn, Name, N - 1)
    end.

%% Drop server-to-client bytes from now on.
hold_down(Relay) -> relay_call(Relay, hold_down).

stop_relay(Relay) -> Relay ! stop.

assert_closed_within(Conn, T0) ->
    receive
        {h2, Conn, {closed, _}} ->
            ?assert(now_ms() - T0 < ?BOUND)
    after 10000 ->
        error(no_closed)
    end.

now_ms() -> erlang:monotonic_time(millisecond).

certs() ->
    Dir = filename:join("/tmp", "h2_tls_close_" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Cert = filename:join(Dir, "cert.pem"),
    Key = filename:join(Dir, "key.pem"),
    case filelib:is_regular(Cert) of
        true -> ok;
        false ->
            _ = os:cmd(lists:flatten(io_lib:format(
                  "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s -days 1 "
                  "-nodes -subj '/CN=localhost' 2>/dev/null", [Key, Cert]))),
            ok
    end,
    #{server => {Cert, Key}}.

-endif.
