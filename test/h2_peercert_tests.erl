%% @doc h2:peercert/1 returns the peer's TLS certificate (DER), read inside the
%% connection process. A server only gets a client certificate when it asks
%% for one with `verify => verify_peer' and `cacerts'.
-module(h2_peercert_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

peercert_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"server sees the client certificate", {timeout, 30, fun client_cert/0}},
      {"no client certificate", {timeout, 30, fun no_client_cert/0}},
      {"cleartext has no certificate", {timeout, 30, fun cleartext/0}},
      {"answers after GOAWAY on both ends", {timeout, 30, fun after_goaway/0}}]}.

client_cert() ->
    #{client := {CCert, CKey}} = Certs = certs(),
    {Client, Server, Ref} = tls(Certs, [{certfile, CCert}, {keyfile, CKey}]),
    try
        ?assertEqual({ok, der(CCert)}, h2:peercert(Server))
    after
        stop(Client, Ref)
    end.

no_client_cert() ->
    {Client, Server, Ref} = tls(certs(), []),
    try
        ?assertEqual({error, no_peercert}, h2:peercert(Server))
    after
        stop(Client, Ref)
    end.

cleartext() ->
    Self = self(),
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => handler(Self)}),
    {ok, Client} = h2:connect("127.0.0.1", h2:server_port(Ref), #{transport => tcp}),
    try
        Server = server_conn(Client),
        ?assertEqual({error, no_peercert}, h2:peercert(Server)),
        ?assertEqual({error, no_peercert}, h2:peercert(Client))
    after
        stop(Client, Ref)
    end.

after_goaway() ->
    #{server := {SCert, _}, client := {CCert, CKey}} = Certs = certs(),
    {Client, Server, Ref} = tls(Certs, [{certfile, CCert}, {keyfile, CKey}]),
    try
        ok = h2:goaway(Server),
        receive {h2, Client, {goaway, _, _}} -> ok after 5000 -> error(no_goaway) end,
        %% Server is in goaway_sent, client in goaway_received.
        ?assertEqual({ok, der(CCert)}, h2:peercert(Server)),
        ?assertEqual({ok, der(SCert)}, h2:peercert(Client))
    after
        stop(Client, Ref)
    end.

%% ---------------------------------------------------------------------------

%% fail_if_no_peer_cert => false lets a client without a certificate in,
%% so peercert/1 can report that it sent none.
tls(#{server := {SCert, SKey}, ca := CA}, ClientSsl) ->
    Self = self(),
    {ok, Ref} = h2:start_server(0, #{cert => SCert, key => SKey,
                                     verify => verify_peer,
                                     cacerts => [der(CA)],
                                     ssl_opts => [{fail_if_no_peer_cert, false}],
                                     handler => handler(Self)}),
    {ok, Client} = h2:connect("localhost", h2:server_port(Ref),
                              #{ssl_opts => [{verify, verify_none} | ClientSsl]}),
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

der(PemFile) ->
    {ok, Pem} = file:read_file(PemFile),
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(Pem),
    Der.

%% A self-signed server cert, and a client cert signed by a test CA: OTP
%% rejects a self-signed client cert even when it is listed in cacerts.
certs() ->
    Dir = filename:join("/tmp", "h2_peercert_" ++ os:getpid()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    F = fun(N) -> filename:join(Dir, N) end,
    case filelib:is_regular(F("client-cert.pem")) of
        true -> ok;
        false ->
            Cmds = [
                "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s -days 1 "
                "-nodes -subj '/CN=localhost'",
                "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s -days 1 "
                "-nodes -subj '/CN=test-ca'",
                "openssl req -newkey rsa:2048 -keyout ~s -out ~s -nodes "
                "-subj '/CN=client'",
                "openssl x509 -req -in ~s -CA ~s -CAkey ~s -CAcreateserial "
                "-out ~s -days 1"],
            Args = [[F("server-key.pem"), F("server-cert.pem")],
                    [F("ca-key.pem"), F("ca-cert.pem")],
                    [F("client-key.pem"), F("client.csr")],
                    [F("client.csr"), F("ca-cert.pem"), F("ca-key.pem"),
                     F("client-cert.pem")]],
            [os:cmd(lists:flatten(io_lib:format(C ++ " 2>/dev/null", A)))
             || {C, A} <- lists:zip(Cmds, Args)],
            ok
    end,
    #{server => {F("server-cert.pem"), F("server-key.pem")},
      client => {F("client-cert.pem"), F("client-key.pem")},
      ca => F("ca-cert.pem")}.

-endif.
