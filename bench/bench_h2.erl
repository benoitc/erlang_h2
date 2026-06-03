-module(bench_h2).
-export([start/1]).

start([PortStr]) ->
    Port = list_to_integer(PortStr),
    {ok, _} = application:ensure_all_started(h2),
    Body = <<"Hello, World!">>,
    Hdrs = [{<<"content-type">>, <<"text/plain">>}],
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        h2:send_response(Conn, Sid, 200, Hdrs),
        h2:send_data(Conn, Sid, Body, true)
    end,
    {ok, _} = h2:start_server(Port, #{transport => tcp, handler => Handler}),
    io:format("h2 server listening on ~p (schedulers=~p)~n",
              [Port, erlang:system_info(schedulers)]),
    receive stop -> ok end.
