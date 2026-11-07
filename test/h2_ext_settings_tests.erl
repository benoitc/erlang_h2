%% @doc Extension settings passed under a raw 16-bit id, such as
%% SETTINGS_WT_ENABLED (0x2b67) for WebTransport over HTTP/2, reach the peer
%% in both directions.
-module(h2_ext_settings_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(WT_ENABLED, 16#2b67).

ext_settings_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"the client sees a server extension setting",
       {timeout, 30, fun server_to_client/0}},
      {"the server sees a client extension setting",
       {timeout, 30, fun client_to_server/0}},
      {"our own extension setting shows once acked",
       {timeout, 30, fun local_after_ack/0}}]}.

server_to_client() ->
    {Ref, Port} = start_server(#{?WT_ENABLED => 1}, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    try
        ok = h2:wait_connected(Conn),
        ?assertEqual(1, maps:get(?WT_ENABLED, h2:get_peer_settings(Conn), undefined))
    after
        stop(Conn, Ref)
    end.

client_to_server() ->
    {Ref, Port} = start_server(#{}, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port,
                            #{transport => tcp, settings => #{?WT_ENABLED => 1}}),
    try
        ok = h2:wait_connected(Conn),
        {ok, _} = h2:request(Conn, <<"GET">>, <<"/">>,
                             [{<<"host">>, <<"127.0.0.1">>}]),
        PeerSettings = receive
                           {server_peer_settings, S} -> S
                       after 5000 ->
                           error(no_request)
                       end,
        ?assertEqual(1, maps:get(?WT_ENABLED, PeerSettings, undefined))
    after
        stop(Conn, Ref)
    end.

local_after_ack() ->
    {Ref, Port} = start_server(#{}, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port,
                            #{transport => tcp, settings => #{?WT_ENABLED => 1}}),
    try
        ok = h2:wait_connected(Conn),
        ?assertEqual(1, maps:get(?WT_ENABLED, h2:get_settings(Conn), undefined))
    after
        stop(Conn, Ref)
    end.

%% The handler reports the client's settings as the server sees them.
start_server(Settings, TestPid) ->
    Handler = fun(Conn, StreamId, _Method, _Path, _Headers) ->
                      TestPid ! {server_peer_settings, h2:get_peer_settings(Conn)},
                      h2:send_response(Conn, StreamId, 200, []),
                      h2:send_data(Conn, StreamId, <<>>, true)
              end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler,
                                     settings => Settings}),
    {Ref, h2:server_port(Ref)}.

stop(Conn, Ref) ->
    try h2:close(Conn) catch exit:_ -> ok end,
    h2:stop_server(Ref).

-endif.
