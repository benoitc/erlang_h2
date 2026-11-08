%% @doc A server started with h2:start_server/2 keeps accepting connections
%% after the process that started it exits, normally or killed, over TCP and
%% TLS. stop_server/1 still closes the socket and the connections from any
%% process.
-module(h2_listener_owner_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

listener_owner_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"tcp: starter returns", {timeout, 30, fun() -> survives(tcp, normal) end}},
      {"tcp: starter killed",  {timeout, 30, fun() -> survives(tcp, kill) end}},
      {"tls: starter returns", {timeout, 30, fun() -> survives(ssl, normal) end}},
      {"tls: starter killed",  {timeout, 30, fun() -> survives(ssl, kill) end}},
      {"stop_server/1 from another process closes everything",
       {timeout, 30, fun stop_from_other_process/0}}]}.

survives(Transport, How) ->
    Server = start_from_short_lived(Transport, How),
    try
        ?assertEqual({ok, 200}, get(Transport, h2:server_port(Server)))
    after
        ok = h2:stop_server(Server)
    end.

stop_from_other_process() ->
    Server = start_from_short_lived(tcp, normal),
    Port = h2:server_port(Server),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    MRef = erlang:monitor(process, Conn),
    unlink(Conn),
    Self = self(),
    spawn(fun() -> Self ! {stopped, h2:stop_server(Server)} end),
    receive {stopped, R} -> ?assertEqual(ok, R) after 10000 -> error(no_stop) end,
    ?assertEqual({error, econnrefused},
                 gen_tcp:connect("127.0.0.1", Port, [binary], 2000)),
    %% The open connection is torn down with the server.
    receive {'DOWN', MRef, process, Conn, _} -> ok
    after 5000 -> error(connection_still_open)
    end.

%% ---------------------------------------------------------------------------

%% Start the server from a process that then exits, either by returning or by
%% being killed, before anyone connects.
start_from_short_lived(Transport, How) ->
    Self = self(),
    Opts = server_opts(Transport),
    Starter = spawn(fun() ->
        Self ! {started, self(), h2:start_server(0, Opts)},
        case How of
            normal -> ok;
            kill   -> receive after infinity -> ok end
        end
    end),
    MRef = erlang:monitor(process, Starter),
    Server = receive {started, Starter, {ok, S}} -> S
             after 5000 -> error(not_started) end,
    case How of
        kill -> exit(Starter, kill);
        normal -> ok
    end,
    receive {'DOWN', MRef, process, Starter, _} -> ok end,
    %% Give a closed socket time to show before connecting.
    timer:sleep(100),
    Server.

server_opts(tcp) ->
    #{transport => tcp, handler => fun handler/5};
server_opts(ssl) ->
    {Cert, Key} = gen_certs(),
    #{cert => Cert, key => Key, handler => fun handler/5}.

handler(Conn, StreamId, _Method, _Path, _Headers) ->
    h2:send_response(Conn, StreamId, 200, []),
    h2:send_data(Conn, StreamId, <<"ok">>, true).

get(Transport, Port) ->
    ConnOpts = case Transport of
        tcp -> #{transport => tcp};
        ssl -> #{ssl_opts => [{verify, verify_none}]}
    end,
    {ok, Conn} = h2:connect("127.0.0.1", Port, ConnOpts),
    try
        {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>,
                               [{<<"host">>, <<"127.0.0.1">>}]),
        receive {h2, Conn, {response, Sid, Status, _}} -> {ok, Status}
        after 5000 -> {error, timeout}
        end
    after
        _ = h2:close(Conn)
    end.

gen_certs() ->
    Dir = filename:join("/tmp", "h2_listener_owner_" ++ os:getpid()),
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
