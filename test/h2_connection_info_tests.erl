%% @doc h2:connection_info/1 reports the transport and, over TLS, the
%% negotiated version and ALPN on both ends. draft-ietf-webtrans-http2 §7
%% needs the TLS version to decide whether WebTransport is allowed.
-module(h2_connection_info_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

connection_info_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"TLS 1.3 reports version and ALPN on both ends",
       {timeout, 30, fun tls13/0}},
      {"a server limited to TLS 1.2 reports tlsv1.2",
       {timeout, 30, fun tls12/0}},
      {"cleartext reports tcp and no TLS version",
       {timeout, 30, fun cleartext/0}}]}.

tls13() ->
    {Client, Server, Ref} = connect(#{}),
    try
        ?assertMatch({ok, #{transport := ssl, tls_version := 'tlsv1.3',
                            alpn := <<"h2">>}}, h2:connection_info(Client)),
        ?assertMatch({ok, #{transport := ssl, tls_version := 'tlsv1.3',
                            alpn := <<"h2">>, sni_hostname := "localhost"}},
                     h2:connection_info(Server))
    after
        stop(Client, Ref)
    end.

tls12() ->
    {Client, Server, Ref} = connect(#{ssl_opts => [{versions, ['tlsv1.2']}]}),
    try
        ?assertMatch({ok, #{transport := ssl, tls_version := 'tlsv1.2'}},
                     h2:connection_info(Client)),
        ?assertMatch({ok, #{transport := ssl, tls_version := 'tlsv1.2'}},
                     h2:connection_info(Server))
    after
        stop(Client, Ref)
    end.

cleartext() ->
    Self = self(),
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => handler(Self)}),
    {ok, Client} = h2:connect("127.0.0.1", h2:server_port(Ref), #{transport => tcp}),
    try
        Server = server_conn(Client),
        {ok, CInfo} = h2:connection_info(Client),
        {ok, SInfo} = h2:connection_info(Server),
        ?assertEqual(#{transport => tcp}, CInfo),
        ?assertEqual(#{transport => tcp}, SInfo)
    after
        stop(Client, Ref)
    end.

%% ---------------------------------------------------------------------------

connect(ServerExtra) ->
    {Cert, Key} = gen_certs(),
    Self = self(),
    {ok, Ref} = h2:start_server(0, maps:merge(#{cert => Cert, key => Key,
                                                handler => handler(Self)},
                                              ServerExtra)),
    {ok, Client} = h2:connect("localhost", h2:server_port(Ref),
                              #{ssl_opts => [{verify, verify_none},
                                             {server_name_indication, "localhost"}]}),
    {Client, server_conn(Client), Ref}.

handler(Test) ->
    fun(Conn, StreamId, _Method, _Path, _Headers) ->
        Test ! {server_conn, Conn},
        h2:send_response(Conn, StreamId, 200, []),
        h2:send_data(Conn, StreamId, <<>>, true)
    end.

server_conn(Client) ->
    {ok, _} = h2:request(Client, <<"GET">>, <<"/">>, [{<<"host">>, <<"localhost">>}]),
    receive {server_conn, C} -> C after 5000 -> error(no_server_conn) end.

stop(Client, Ref) ->
    _ = h2:close(Client),
    ok = h2:stop_server(Ref).

gen_certs() ->
    Dir = filename:join("/tmp", "h2_connection_info_" ++ os:getpid()),
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
