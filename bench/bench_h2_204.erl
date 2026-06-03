-module(bench_h2_204).
-export([start/1]).

%% Same as bench_h2 but replies 204 (body-forbidden): ONE send_response call,
%% ONE socket write, no send_data. Used to measure the cost of the second
%% round-trip + second write that a 200+body response incurs.
start([PortStr]) ->
    Port = list_to_integer(PortStr),
    {ok, _} = application:ensure_all_started(h2),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        h2:send_response(Conn, Sid, 204, [])
    end,
    {ok, _} = h2:start_server(Port, #{transport => tcp, handler => Handler}),
    io:format("h2 204 server listening on ~p~n", [Port]),
    receive stop -> ok end.
