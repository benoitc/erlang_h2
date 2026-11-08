%% @doc Listener process: owns the listen socket and supervises the
%% acceptor pool. Runs under `h2_sup', and `h2:start_server/2' hands it the
%% listen socket, so the server outlives the process that started it.
-module(h2_listener).

-export([start_link/1, stop/2]).
-export([init/2]).

-type transport() :: ssl | tcp.

-type args() :: #{transport := transport(),
                  listen_socket := term(),
                  acceptor_count := pos_integer(),
                  ref := reference(),
                  acceptor_fun := fun((term()) -> no_return()),
                  server_state := map()}.

-spec start_link(args()) -> {ok, pid()}.
start_link(Args) ->
    proc_lib:start_link(?MODULE, init, [self(), Args]).

%% @doc Stop the listener and wait until it is gone, so the listen socket is
%% closed when this returns. Safe to call on a listener that already exited.
-spec stop(pid(), reference()) -> ok.
stop(Pid, Ref) ->
    MRef = erlang:monitor(process, Pid),
    Pid ! {stop, Ref},
    receive
        {'DOWN', MRef, process, Pid, _} -> ok
    after 5000 ->
        exit(Pid, kill),
        receive {'DOWN', MRef, process, Pid, _} -> ok end
    end.

init(Parent, #{transport := Transport,
               listen_socket := ListenSocket,
               acceptor_count := NumAcceptors,
               ref := Ref,
               acceptor_fun := AcceptorFun,
               server_state := ServerState}) ->
    process_flag(trap_exit, true),
    AcceptorPids = [spawn_link(fun() -> AcceptorFun(ServerState) end)
                    || _ <- lists:seq(1, NumAcceptors)],
    proc_lib:init_ack(Parent, {ok, self()}),
    loop(Transport, ListenSocket, AcceptorPids, Ref).

loop(Transport, ListenSocket, AcceptorPids, Ref) ->
    receive
        {stop, Ref} ->
            lists:foreach(fun(Pid) -> exit(Pid, shutdown) end, AcceptorPids),
            close(Transport, ListenSocket),
            ok;
        {'EXIT', Pid, _Reason} ->
            loop(Transport, ListenSocket, lists:delete(Pid, AcceptorPids), Ref);
        Other ->
            logger:debug("h2_listener: unexpected message ~tp", [Other]),
            loop(Transport, ListenSocket, AcceptorPids, Ref)
    end.

close(ssl, Sock) -> _ = ssl:close(Sock), ok;
close(tcp, Sock) -> _ = gen_tcp:close(Sock), ok.
