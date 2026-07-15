%% @doc Tests for h2:peername/1. Over loopback the accessor must return a real
%% {IpAddress, Port} for a live connection, on the server side (where an
%% embedder needs the remote client's address) as well as the client side.
-module(h2_peername_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

peername_test_() ->
    {timeout, 30, fun peername/0}.

peername() ->
    {ok, _} = application:ensure_all_started(h2),
    Self = self(),
    Handler = fun(Conn, StreamId, _Method, _Path, _Headers) ->
        Self ! {server_conn, Conn},
        h2:send_response(Conn, StreamId, 200,
                         [{<<"content-type">>, <<"text/plain">>}]),
        h2:send_data(Conn, StreamId, <<"ok">>, true)
    end,
    {ok, Server} = h2:start_server(0, #{handler   => Handler,
                                        transport => tcp}),
    Port = h2:server_port(Server),
    {ok, Client} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Client),

    {ok, _} = h2:request(Client, <<"GET">>, <<"/">>,
                         [{<<"host">>, authority(Port)}]),

    ServerConn = receive {server_conn, C} -> C after 2000 -> error(no_server_conn) end,

    %% Server side: the remote client's ephemeral address.
    ?assertMatch({ok, {{127,0,0,1}, _ClientPort}}, h2:peername(ServerConn)),
    %% Client side: the server's listen port.
    ?assertEqual({ok, {{127,0,0,1}, Port}}, h2:peername(Client)),

    _ = h2:close(Client),
    ok = h2:stop_server(Server),
    ok.

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

-endif.
