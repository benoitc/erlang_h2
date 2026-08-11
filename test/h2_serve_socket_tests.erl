%% @doc Tests for h2:serve_socket/2 — serving a socket the caller accepted and
%% handshook itself, which is what an embedder owning a single dual-stack TLS
%% listener needs.
%%
%% Also covers two branches of the built-in TLS acceptor that nothing else
%% exercised: what a non-h2 client gets when it hits the h2 listener, and
%% `ssl_opts' overriding the default `alpn_preferred_protocols'.
-module(h2_serve_socket_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

serve_socket_test_() ->
    {timeout, 60,
     [fun serves_request/0,
      fun teardown_on_client_disconnect/0,
      fun settings_pass_through/0]}.

alpn_test_() ->
    {timeout, 60,
     [fun non_h2_client_is_closed/0,
      fun http1_only_client_is_rejected/0,
      fun ssl_opts_override_alpn/0]}.

%% A socket accepted and handshaken outside the library, handed to
%% serve_socket/2, serves a normal request.
serves_request() ->
    {ok, _} = application:ensure_all_started(h2),
    {LSock, Port} = listen([<<"h2">>, <<"http/1.1">>]),
    Acceptor = accept_and_serve(LSock, #{handler => fun echo_handler/5}, self()),

    {ok, Client} = connect(Port),
    {ok, Sid} = h2:request(Client, <<"GET">>, <<"/">>,
                           [{<<"host">>, authority(Port)}]),

    {ok, _ServePid} = wait_served(),
    ?assertEqual(200, wait_status(Client, Sid)),
    ?assertEqual(<<"served">>, collect_body(Client, Sid, <<>>)),

    cleanup(Client, Acceptor, LSock).

%% The connection process returned by serve_socket/2 exits `normal' when the
%% client goes away, so an embedder that links to it isn't taken down.
teardown_on_client_disconnect() ->
    {ok, _} = application:ensure_all_started(h2),
    {LSock, Port} = listen([<<"h2">>]),
    Acceptor = accept_and_serve(LSock, #{handler => fun echo_handler/5}, self()),

    {ok, Client} = connect(Port),
    {ok, Sid} = h2:request(Client, <<"GET">>, <<"/">>,
                           [{<<"host">>, authority(Port)}]),
    {ok, ServePid} = wait_served(),
    ?assertEqual(200, wait_status(Client, Sid)),

    MRef = erlang:monitor(process, ServePid),
    _ = h2:close(Client),
    receive
        {'DOWN', MRef, process, ServePid, Reason} ->
            ?assertEqual(normal, Reason)
    after 5000 ->
        error(connection_still_alive)
    end,
    %% The acceptor is linked to the connection; a normal exit leaves it alone.
    ?assert(is_process_alive(Acceptor)),

    cleanup(undefined, Acceptor, LSock).

%% An option handed to serve_socket/2 reaches the connection: the client sees
%% the server's SETTINGS_MAX_CONCURRENT_STREAMS.
settings_pass_through() ->
    {ok, _} = application:ensure_all_started(h2),
    {LSock, Port} = listen([<<"h2">>]),
    Opts = #{handler  => fun echo_handler/5,
             settings => #{max_concurrent_streams => 3}},
    Acceptor = accept_and_serve(LSock, Opts, self()),

    {ok, Client} = connect(Port),
    {ok, Sid} = h2:request(Client, <<"GET">>, <<"/">>,
                           [{<<"host">>, authority(Port)}]),
    {ok, _} = wait_served(),
    %% Wait for the response so the server's SETTINGS have certainly landed.
    ?assertEqual(200, wait_status(Client, Sid)),

    Peer = h2:get_peer_settings(Client),
    ?assertEqual(3, maps:get(max_concurrent_streams, Peer)),

    cleanup(Client, Acceptor, LSock).

%% A TLS client that advertises no ALPN at all completes the handshake against
%% the h2 listener and is then closed: h2 will not assume h2 (RFC 9113 §3.3).
non_h2_client_is_closed() ->
    {ok, _} = application:ensure_all_started(h2),
    {Cert, Key} = gen_certs(),
    {ok, Server} = h2:start_server(0, #{handler => fun echo_handler/5,
                                        cert => Cert, key => Key}),
    Port = h2:server_port(Server),

    {ok, Sock} = ssl:connect("127.0.0.1", Port, client_opts(), 10000),
    ?assertEqual({error, protocol_not_negotiated}, ssl:negotiated_protocol(Sock)),
    ?assertEqual({error, closed}, ssl:recv(Sock, 0, 5000)),

    _ = ssl:close(Sock),
    ok = h2:stop_server(Server).

%% A client offering only http/1.1 never gets that far: with the default
%% preferred list of [h2] there is no overlap, so TLS itself fails.
http1_only_client_is_rejected() ->
    {ok, _} = application:ensure_all_started(h2),
    {Cert, Key} = gen_certs(),
    {ok, Server} = h2:start_server(0, #{handler => fun echo_handler/5,
                                        cert => Cert, key => Key}),
    Port = h2:server_port(Server),

    Opts = [{alpn_advertised_protocols, [<<"http/1.1">>]} | client_opts()],
    ?assertMatch({error, _}, ssl:connect("127.0.0.1", Port, Opts, 10000)),

    ok = h2:stop_server(Server).

%% `ssl_opts' is merged last, so it can widen the listener's ALPN list. This is
%% the listener shape a dual-stack embedder runs; the built-in acceptor still
%% closes whatever isn't h2.
ssl_opts_override_alpn() ->
    {ok, _} = application:ensure_all_started(h2),
    {Cert, Key} = gen_certs(),
    {ok, Server} = h2:start_server(0, #{
        handler  => fun echo_handler/5,
        cert     => Cert,
        key      => Key,
        ssl_opts => [{alpn_preferred_protocols, [<<"h2">>, <<"http/1.1">>]}]
    }),
    Port = h2:server_port(Server),

    Opts = [{alpn_advertised_protocols, [<<"http/1.1">>]} | client_opts()],
    {ok, Sock} = ssl:connect("127.0.0.1", Port, Opts, 10000),
    ?assertEqual({ok, <<"http/1.1">>}, ssl:negotiated_protocol(Sock)),
    ?assertEqual({error, closed}, ssl:recv(Sock, 0, 5000)),

    _ = ssl:close(Sock),
    %% h2 still works on the same listener.
    {ok, Client} = connect(Port),
    {ok, Sid} = h2:request(Client, <<"GET">>, <<"/">>,
                           [{<<"host">>, authority(Port)}]),
    ?assertEqual(200, wait_status(Client, Sid)),

    _ = h2:close(Client),
    ok = h2:stop_server(Server).

%% ---- helpers ----

echo_handler(Conn, StreamId, _Method, _Path, _Headers) ->
    h2:send_response(Conn, StreamId, 200,
                     [{<<"content-type">>, <<"text/plain">>}]),
    h2:send_data(Conn, StreamId, <<"served">>, true).

%% Own the listener the way an embedder would.
listen(ALPN) ->
    {Cert, Key} = gen_certs(),
    {ok, LSock} = ssl:listen(0, [{certfile, Cert},
                                 {keyfile, Key},
                                 {alpn_preferred_protocols, ALPN},
                                 {versions, ['tlsv1.2', 'tlsv1.3']},
                                 {reuseaddr, true},
                                 {active, false},
                                 {mode, binary}]),
    {ok, {_, Port}} = ssl:sockname(LSock),
    {LSock, Port}.

%% Accept one connection, complete the handshake and the ALPN decision here,
%% then hand the socket over. Stays alive afterwards because serve_socket/2
%% links the connection to whoever called it.
accept_and_serve(LSock, Opts, Parent) ->
    spawn(fun() ->
        {ok, Sock} = ssl:transport_accept(LSock, 15000),
        {ok, TLS} = ssl:handshake(Sock, 15000),
        {ok, <<"h2">>} = ssl:negotiated_protocol(TLS),
        Parent ! {served, h2:serve_socket(TLS, Opts)},
        receive stop -> ok end
    end).

wait_served() ->
    receive
        {served, Result} ->
            ?assertMatch({ok, Pid} when is_pid(Pid), Result),
            Result
    after 15000 ->
        error(never_served)
    end.

connect(Port) ->
    h2:connect("127.0.0.1", Port, #{transport => ssl, verify => verify_none}).

client_opts() ->
    [{verify, verify_none}, {active, false}, {mode, binary},
     {versions, ['tlsv1.2', 'tlsv1.3']}].

wait_status(Conn, Sid) ->
    receive
        {h2, Conn, {response, Sid, Status, _Headers}} -> Status
    after 15000 ->
        error(no_response)
    end.

collect_body(Conn, Sid, Acc) ->
    receive
        {h2, Conn, {data, Sid, Data, true}}  -> <<Acc/binary, Data/binary>>;
        {h2, Conn, {data, Sid, Data, false}} -> collect_body(Conn, Sid, <<Acc/binary, Data/binary>>);
        {h2, Conn, _Other}                   -> collect_body(Conn, Sid, Acc)
    after 15000 ->
        error({timeout, byte_size(Acc)})
    end.

cleanup(Client, Acceptor, LSock) ->
    case Client of
        undefined -> ok;
        _         -> _ = h2:close(Client), ok
    end,
    Acceptor ! stop,
    ok = ssl:close(LSock).

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

gen_certs() ->
    Dir = filename:join("/tmp", "h2_serve_socket_" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Cert = filename:join(Dir, "cert.pem"),
    Key  = filename:join(Dir, "key.pem"),
    case filelib:is_regular(Cert) andalso filelib:is_regular(Key) of
        true -> ok;
        false ->
            Cmd = io_lib:format(
                "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
                "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null", [Key, Cert]),
            _ = os:cmd(lists:flatten(Cmd)),
            ok
    end,
    {Cert, Key}.

-endif.
