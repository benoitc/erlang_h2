%% @doc draft-ietf-webtrans-http2 §3.1: SETTINGS_WT_ENABLED (0x2b67) can change
%% during the connection. With `notify_peer_settings => true' the owner is told
%% after every peer SETTINGS frame is applied and acked, the first one included;
%% without it nothing is sent.
-module(h2_peer_settings_notify_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-export([handle_request/5, handle_peer_settings/2]).

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(WT_ENABLED, 16#2b67).

notify_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"client is told about every peer SETTINGS frame",
       {timeout, 30, fun client_notified/0}},
      {"no message without the option",
       {timeout, 30, fun client_not_notified/0}},
      {"module handler gets handle_peer_settings/2 on the server",
       {timeout, 30, fun server_notified/0}}]}.

client_notified() ->
    {LSock, Port} = listen(),
    {ok, Conn} = h2:connect("127.0.0.1", Port,
                            #{transport => tcp, notify_peer_settings => true}),
    try
        First = receive {h2, Conn, {peer_settings, S1}} -> S1
                after 5000 -> error(no_first_settings) end,
        ?assertEqual(1, maps:get(?WT_ENABLED, First)),
        ?assertEqual(First, h2:get_peer_settings(Conn)),
        server_send(second_settings),
        Second = receive {h2, Conn, {peer_settings, S2}} -> S2
                 after 5000 -> error(no_second_settings) end,
        ?assertMatch(#{?WT_ENABLED := 2}, Second),
        ?assertEqual(Second, h2:get_peer_settings(Conn))
    after
        _ = h2:close(Conn),
        gen_tcp:close(LSock)
    end.

client_not_notified() ->
    {LSock, Port} = listen(),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    try
        server_send(second_settings),
        %% A later SETTINGS frame is still applied, but nobody is told.
        wait_until(fun() ->
            maps:get(?WT_ENABLED, h2:get_peer_settings(Conn), undefined) =:= 2
        end),
        receive {h2, Conn, {peer_settings, _}} = M -> error({unexpected, M})
        after 200 -> ok end
    after
        _ = h2:close(Conn),
        gen_tcp:close(LSock)
    end.

server_notified() ->
    register(?MODULE, self()),
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => ?MODULE,
                                     notify_peer_settings => true}),
    {ok, Conn} = h2:connect("127.0.0.1", h2:server_port(Ref),
                            #{transport => tcp, settings => #{?WT_ENABLED => 1}}),
    try
        Got = receive {server_peer_settings, _ServerConn, S} -> S
              after 5000 -> error(no_server_notification) end,
        ?assertEqual(1, maps:get(?WT_ENABLED, Got))
    after
        unregister(?MODULE),
        _ = h2:close(Conn),
        ok = h2:stop_server(Ref)
    end.

handle_request(Conn, StreamId, _Method, _Path, _Headers) ->
    h2:send_response(Conn, StreamId, 200, []),
    h2:send_data(Conn, StreamId, <<>>, true).

handle_peer_settings(Conn, Settings) ->
    ?MODULE ! {server_peer_settings, Conn, Settings}.

%% ---------------------------------------------------------------------------
%% Raw h2c server peer: sends SETTINGS with WT_ENABLED=1, acks the client's
%% SETTINGS, and on request sends a second SETTINGS with WT_ENABLED=2.

listen() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {packet, raw},
                                     {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Test = self(),
    Pid = spawn_link(fun() -> peer(LSock, Test) end),
    put(peer, Pid),
    {LSock, Port}.

server_send(What) ->
    get(peer) ! What.

peer(LSock, Test) ->
    {ok, Sock} = gen_tcp:accept(LSock, 5000),
    {ok, ?PREFACE} = gen_tcp:recv(Sock, byte_size(?PREFACE), 5000),
    ok = gen_tcp:send(Sock, [h2_frame:encode(h2_frame:settings([{?WT_ENABLED, 1}])),
                             h2_frame:encode(h2_frame:settings_ack())]),
    ok = inet:setopts(Sock, [{active, true}]),
    peer_loop(Sock, Test).

peer_loop(Sock, Test) ->
    receive
        second_settings ->
            ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:settings([{?WT_ENABLED, 2}]))),
            peer_loop(Sock, Test);
        {tcp, Sock, _} ->
            peer_loop(Sock, Test);
        {tcp_closed, Sock} ->
            ok
    after 30000 ->
        ok
    end.

wait_until(Fun) ->
    wait_until(Fun, 50).

wait_until(_Fun, 0) ->
    error(timeout);
wait_until(Fun, N) ->
    case Fun() of
        true -> ok;
        false -> timer:sleep(50), wait_until(Fun, N - 1)
    end.

-endif.
