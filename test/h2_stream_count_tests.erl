%% @doc Tests for the incrementally maintained stream counters in
%% eh2_connection. The invariant is that active_stream_count /
%% peer_active_stream_count always equal a fresh fold over the live `streams`
%% map (eh2_connection:verify_stream_counts/1). Because put_stream/3 updates the
%% counters atomically with every map write, the invariant must hold at every
%% point, so we drive a mix of stream terminations and assert it on both ends.
-module(h2_stream_count_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

stream_count_invariant_test_() ->
    {timeout, 60, fun stream_count_invariant/0}.

stream_count_invariant() ->
    {ok, _} = application:ensure_all_started(h2),
    Self = self(),
    Handler = fun(Conn, StreamId, _Method, _Path, _Headers) ->
        Self ! {server_conn, Conn},
        h2:send_response(Conn, StreamId, 200,
                         [{<<"content-type">>, <<"text/plain">>}]),
        h2:send_data(Conn, StreamId, <<"ok">>, true)
    end,
    {ok, Server} = h2:start_server(0, #{handler   => Handler,
                                        transport => tcp,
                                        settings  => #{max_concurrent_streams => 1000}}),
    Port = h2:server_port(Server),
    {ok, Client} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Client),

    %% 1) Many normal GETs: insert -> half_closed_local -> closed on the client,
    %%    open -> half_closed_remote -> closed on the server, and (>100 closed)
    %%    the closed-stream eviction path.
    [ {ok, _} = h2:request(Client, <<"GET">>,
                           <<"/", (integer_to_binary(I))/binary>>,
                           [{<<"host">>, authority(Port)}])
      || I <- lists:seq(1, 150) ],

    %% 2) Open-bodied requests, then RST_STREAM: the rst close path while the
    %%    stream is still open / half_closed.
    Open = [ begin
                 {ok, Sid} = h2:request(Client, headers(Port), #{end_stream => false}),
                 Sid
             end || _ <- lists:seq(1, 10) ],
    timer:sleep(100),
    _ = [ h2:cancel(Client, Sid) || Sid <- Open ],

    %% Let both ends drain.
    timer:sleep(500),
    ServerConn = receive {server_conn, C} -> C after 2000 -> error(no_server_conn) end,

    ?assertEqual(ok, eh2_connection:verify_stream_counts(Client)),
    ?assertEqual(ok, eh2_connection:verify_stream_counts(ServerConn)),

    _ = h2:close(Client),
    ok = h2:stop_server(Server),
    ok.

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

headers(Port) ->
    [{<<":method">>,    <<"GET">>},
     {<<":path">>,      <<"/open">>},
     {<<":scheme">>,    <<"http">>},
     {<<":authority">>, authority(Port)}].

-endif.
