-module(bench_h2_respond).
-export([start/1]).

%% Same "Hello, World!" response as bench_h2 but using the combined h2:respond/5
%% fast path: one gen_statem call + one coalesced socket write per request.
start([PortStr]) ->
    Port = list_to_integer(PortStr),
    {ok, _} = application:ensure_all_started(h2),
    Body = <<"Hello, World!">>,
    Hdrs = [{<<"content-type">>, <<"text/plain">>}],
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        h2:respond(Conn, Sid, 200, Hdrs, Body)
    end,
    {ok, _} = h2:start_server(Port, #{transport => tcp, handler => Handler}),
    io:format("h2 respond/5 server listening on ~p~n", [Port]),
    receive stop -> ok end.
