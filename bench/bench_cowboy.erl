-module(bench_cowboy).
-export([start/1]).

start([PortStr]) ->
    Port = list_to_integer(PortStr),
    {ok, _} = application:ensure_all_started(cowboy),
    Dispatch = cowboy_router:compile([{'_', [{"/", bench_cowboy_h, []}]}]),
    {ok, _} = cowboy:start_clear(http, [{port, Port}],
                                 #{env => #{dispatch => Dispatch}}),
    io:format("cowboy server listening on ~p (schedulers=~p)~n",
              [Port, erlang:system_info(schedulers)]),
    receive stop -> ok end.
