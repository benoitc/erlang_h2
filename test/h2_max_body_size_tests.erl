%% @doc `max_body_size': the most body bytes one stream may receive.
%%
%% Server side, a request that declares more is answered 413 before its handler
%% runs, and one that sends more is answered 413 while no response has started.
%% Client side, a response over the limit is cancelled and the requester gets
%% `{stream_reset, StreamId, body_too_large}'. Under the limit, nothing changes.
-module(h2_max_body_size_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(LIMIT, 100).

max_body_size_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"a request body under the limit is served",
       {timeout, 30, fun under_the_limit/0}},
      {"a request that declares too much is answered 413, unseen by its handler",
       {timeout, 30, fun declared_too_large/0}},
      {"a request that sends too much with no length is answered 413",
       {timeout, 30, fun sent_too_large/0}},
      {"a response over the client's limit is cancelled",
       {timeout, 30, fun response_too_large/0}}]}.

under_the_limit() ->
    Handler = fun(Conn, Sid, _M, _P, _H) ->
                      ok = h2:respond(Conn, Sid, 200, [], <<"ok">>)
              end,
    with_server(#{max_body_size => ?LIMIT}, Handler, fun(Client, Port) ->
        {ok, Sid} = h2:request(Client, <<"POST">>, <<"/">>,
                               headers(Port, 10), body(10)),
        ?assertEqual(200, status(Client, Sid))
    end).

declared_too_large() ->
    Test = self(),
    Handler = fun(_Conn, _Sid, _M, _P, _H) -> Test ! handler_ran end,
    with_server(#{max_body_size => ?LIMIT}, Handler, fun(Client, Port) ->
        {ok, Sid} = open(Client, Port, [{<<"content-length">>, <<"1000">>}]),
        ?assertEqual(413, status(Client, Sid)),
        receive handler_ran -> ?assert(false) after 200 -> ok end
    end).

sent_too_large() ->
    Handler = fun(_Conn, _Sid, _M, _P, _H) -> ok end,
    with_server(#{max_body_size => ?LIMIT}, Handler, fun(Client, Port) ->
        {ok, Sid} = open(Client, Port, []),
        ok = h2:send_data(Client, Sid, body(1000), true),
        ?assertEqual(413, status(Client, Sid))
    end).

response_too_large() ->
    Handler = fun(Conn, Sid, _M, _P, _H) ->
                      ok = h2:respond(Conn, Sid, 200, [], body(1000))
              end,
    {ok, Server} = h2:start_server(0, #{handler => Handler, transport => tcp}),
    Port = h2:server_port(Server),
    try
        {ok, Client} = h2:connect("127.0.0.1", Port,
                                  #{transport => tcp, max_body_size => ?LIMIT}),
        ok = h2:wait_connected(Client),
        {ok, Sid} = h2:request(Client, <<"GET">>, <<"/">>,
                               [{<<"host">>, authority(Port)}]),
        ?assertEqual(body_too_large, reset_reason(Client, Sid)),
        _ = h2:close(Client)
    after
        ok = h2:stop_server(Server)
    end.

%% ---- helpers ----

with_server(Opts, Handler, Fun) ->
    {ok, Server} = h2:start_server(0, Opts#{handler => Handler, transport => tcp}),
    Port = h2:server_port(Server),
    try
        {ok, Client} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
        ok = h2:wait_connected(Client),
        Fun(Client, Port),
        _ = h2:close(Client)
    after
        ok = h2:stop_server(Server)
    end.

%% A POST whose body the caller sends afterwards.
open(Client, Port, Extra) ->
    h2:request(Client, [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/">>},
                        {<<":scheme">>, <<"http">>},
                        {<<":authority">>, authority(Port)} | Extra],
               #{end_stream => false}).

headers(Port, Length) ->
    [{<<"host">>, authority(Port)},
     {<<"content-length">>, integer_to_binary(Length)}].

body(N) -> binary:copy(<<"x">>, N).

authority(Port) -> iolist_to_binary(["127.0.0.1:", integer_to_list(Port)]).

status(Conn, Sid) ->
    receive
        {h2, Conn, {response, Sid, Status, _}} -> Status
    after 5000 -> error(no_response)
    end.

reset_reason(Conn, Sid) ->
    receive
        {h2, Conn, {stream_reset, Sid, Reason}} -> Reason;
        {h2, Conn, {response, Sid, _, _}} -> reset_reason(Conn, Sid);
        {h2, Conn, {data, Sid, _, _}} -> reset_reason(Conn, Sid)
    after 5000 -> error(no_reset)
    end.

-endif.
