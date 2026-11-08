%% @doc When h2_sup shuts a listener down (application stop, or
%% supervisor:terminate_child/2), the listener closes its socket and exits at
%% once instead of lingering until the supervisor's 5 s shutdown timeout
%% kills it.
-module(h2_listener_shutdown_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

shutdown_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"supervisor shutdown stops the listener promptly",
       {timeout, 30, fun supervisor_shutdown/0}}]}.

supervisor_shutdown() ->
    Handler = fun(Conn, StreamId, _Method, _Path, _Headers) ->
                      h2:send_response(Conn, StreamId, 200, []),
                      h2:send_data(Conn, StreamId, <<>>, true)
              end,
    {ok, {Listener, _Ref, Port} = _Server} =
        h2:start_server(0, #{transport => tcp, handler => Handler}),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    unlink(Conn),
    CRef = erlang:monitor(process, Conn),
    T0 = erlang:monotonic_time(millisecond),
    ok = supervisor:terminate_child(h2_sup, Listener),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assert(Elapsed < 1000),
    ?assertNot(is_process_alive(Listener)),
    ?assertEqual({error, econnrefused},
                 gen_tcp:connect("127.0.0.1", Port, [binary], 2000)),
    receive {'DOWN', CRef, process, Conn, _} -> ok
    after 5000 -> error(connection_still_open)
    end.

-endif.
