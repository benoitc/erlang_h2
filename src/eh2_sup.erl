-module(eh2_sup).
-behaviour(supervisor).

-export([start_link/0, start_listener/1]).
-export([init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_listener(Args) ->
    supervisor:start_child(?MODULE, [Args]).

init([]) ->
    SupFlags = #{strategy => simple_one_for_one,
                 intensity => 10,
                 period => 10},
    Child = #{id => eh2_listener,
              start => {eh2_listener, start_link, []},
              restart => temporary,
              shutdown => 5000,
              type => worker,
              modules => [eh2_listener]},
    {ok, {SupFlags, [Child]}}.
