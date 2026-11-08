%% @doc draft-ietf-webtrans-http2 §4.3.1: the CONNECT request and the response
%% accepting a session must use the peer SETTINGS acknowledged when they are
%% sent. `report_peer_settings => true' on request/3 and send_response/5
%% returns that map from the same call that writes the HEADERS.
-module(h2_report_peer_settings_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(WT_ENABLED, 16#2b67).

report_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"request/3 returns the peer settings, unchanged by a later SETTINGS",
       {timeout, 30, fun client_snapshot/0}},
      {"request/3 without the option returns {ok, StreamId}",
       {timeout, 30, fun client_default/0}},
      {"send_response/5 returns the client's settings",
       {timeout, 30, fun server_snapshot/0}}]}.

client_snapshot() ->
    {LSock, Port} = listen(),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    try
        {ok, Sid, Snapshot} = h2:request(Conn, get_headers(),
                                         #{report_peer_settings => true}),
        ?assert(is_integer(Sid)),
        ?assertEqual(h2:get_peer_settings(Conn), Snapshot),
        ?assertMatch(#{?WT_ENABLED := 1}, Snapshot),
        server_send(second_settings),
        wait_until(fun() ->
            maps:get(?WT_ENABLED, h2:get_peer_settings(Conn)) =:= 2
        end),
        ?assertMatch(#{?WT_ENABLED := 1}, Snapshot),
        {ok, _, Later} = h2:request(Conn, get_headers(),
                                    #{report_peer_settings => true}),
        ?assertMatch(#{?WT_ENABLED := 2}, Later)
    after
        _ = h2:close(Conn),
        gen_tcp:close(LSock)
    end.

client_default() ->
    {LSock, Port} = listen(),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    try
        ?assertMatch({ok, Sid} when is_integer(Sid),
                     h2:request(Conn, get_headers(), #{}))
    after
        _ = h2:close(Conn),
        gen_tcp:close(LSock)
    end.

server_snapshot() ->
    Self = self(),
    Handler = fun(Conn, StreamId, _Method, <<"/report">>, _Headers) ->
                      R = h2:send_response(Conn, StreamId, 200, [],
                                           #{report_peer_settings => true}),
                      Self ! {reply, report, R, h2:get_peer_settings(Conn)},
                      h2:send_data(Conn, StreamId, <<>>, true);
                 (Conn, StreamId, _Method, _Path, _Headers) ->
                      R = h2:send_response(Conn, StreamId, 200, [], #{}),
                      Self ! {reply, plain, R, undefined},
                      h2:send_data(Conn, StreamId, <<>>, true)
              end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler}),
    {ok, Conn} = h2:connect("127.0.0.1", h2:server_port(Ref),
                            #{transport => tcp, settings => #{?WT_ENABLED => 1}}),
    try
        {ok, _} = h2:request(Conn, <<"GET">>, <<"/report">>,
                             [{<<"host">>, <<"127.0.0.1">>}]),
        receive
            {reply, report, {ok, Snapshot}, Current} ->
                ?assertMatch(#{?WT_ENABLED := 1}, Snapshot),
                ?assertEqual(Current, Snapshot)
        after 5000 -> error(no_reply)
        end,
        {ok, _} = h2:request(Conn, <<"GET">>, <<"/">>,
                             [{<<"host">>, <<"127.0.0.1">>}]),
        receive
            {reply, plain, R, _} -> ?assertEqual(ok, R)
        after 5000 -> error(no_reply)
        end
    after
        _ = h2:close(Conn),
        ok = h2:stop_server(Ref)
    end.

get_headers() ->
    [{<<":method">>, <<"GET">>}, {<<":scheme">>, <<"http">>},
     {<<":path">>, <<"/">>}, {<<":authority">>, <<"127.0.0.1">>}].

%% ---------------------------------------------------------------------------
%% Raw h2c server peer: SETTINGS with WT_ENABLED=1, acks the client, and on
%% request sends a second SETTINGS with WT_ENABLED=2. It never answers
%% requests; the tests only need the HEADERS to have been written.

listen() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {packet, raw},
                                     {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Pid = spawn_link(fun() -> peer(LSock) end),
    put(peer, Pid),
    {LSock, Port}.

server_send(What) ->
    get(peer) ! What.

peer(LSock) ->
    {ok, Sock} = gen_tcp:accept(LSock, 5000),
    {ok, ?PREFACE} = gen_tcp:recv(Sock, byte_size(?PREFACE), 5000),
    ok = gen_tcp:send(Sock, [h2_frame:encode(h2_frame:settings([{?WT_ENABLED, 1}])),
                             h2_frame:encode(h2_frame:settings_ack())]),
    ok = inet:setopts(Sock, [{active, true}]),
    peer_loop(Sock).

peer_loop(Sock) ->
    receive
        second_settings ->
            ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:settings([{?WT_ENABLED, 2}]))),
            peer_loop(Sock);
        {tcp, Sock, _} ->
            peer_loop(Sock);
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
