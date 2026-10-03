%% @doc RST_STREAM stays valid after a GOAWAY in either direction (RFC 9113
%% 6.8): existing streams keep running, and a client needs the reset to drop
%% the streams a peer GOAWAY refused. A raw gen_tcp h2c server built on
%% h2_frame reports every RST_STREAM it receives to the test process.
-module(h2_goaway_cancel_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(CANCEL, 16#8).

goaway_cancel_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"cancel a stream refused by a received GOAWAY",
       {timeout, 30, fun refused_stream_cancel/0}},
      {"cancel an open stream after sending our own GOAWAY",
       {timeout, 30, fun cancel_after_own_goaway/0}}]}.

%% Note: today this case also passes without the goaway_received clause.
%% process_frames/2 ends every read with determine_state_transition/1, which
%% puts a client back in `connected' whenever its settings are acked, so the
%% goaway_received state name chosen by the GOAWAY handler never sticks. The
%% case still pins the observable contract: cancel/2 returns ok and the peer
%% sees RST_STREAM for the refused stream.
refused_stream_cancel() ->
    process_flag(trap_exit, true),
    {Port, Server} = start_server(goaway, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, headers(Port)),
    receive
        {h2, Conn, {goaway, 0, no_error}} -> ok
    after 5000 ->
        error(no_goaway)
    end,
    ?assertEqual(ok, h2:cancel(Conn, StreamId)),
    ?assertEqual({rst_stream, StreamId, ?CANCEL}, wait_rst_stream()),
    cleanup(Conn, Server).

cancel_after_own_goaway() ->
    process_flag(trap_exit, true),
    {Port, Server} = start_server(plain, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, headers(Port)),
    ok = h2:goaway(Conn),
    ?assertEqual(ok, h2:cancel(Conn, StreamId)),
    ?assertEqual({rst_stream, StreamId, ?CANCEL}, wait_rst_stream()),
    cleanup(Conn, Server).

wait_rst_stream() ->
    receive
        {rst_stream, _, _} = Rst -> Rst
    after 5000 ->
        error(no_rst_stream)
    end.

cleanup(Conn, Server) ->
    try h2:close(Conn) catch exit:_ -> ok end,
    Server ! stop,
    receive {'EXIT', Server, _} -> ok after 5000 -> error(server_still_up) end,
    flush().

flush() ->
    receive _ -> flush() after 0 -> ok end.

headers(Port) ->
    [{<<"host">>, iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)])}].

%% ---------------------------------------------------------------------------
%% Raw h2c server. Mode `goaway' answers the first HEADERS with
%% GOAWAY(0, no_error); mode `plain' never sends GOAWAY.
%% ---------------------------------------------------------------------------

start_server(Mode, TestPid) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {packet, raw},
                                     {ip, {127, 0, 0, 1}}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Pid = spawn_link(fun() -> serve(LSock, Mode, TestPid) end),
    {Port, Pid}.

serve(LSock, Mode, TestPid) ->
    {ok, Sock} = gen_tcp:accept(LSock, 5000),
    Rest = read_preface(Sock, <<>>),
    ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:settings([]))),
    loop(Sock, Rest, Mode, TestPid).

read_preface(Sock, Buf) when byte_size(Buf) < byte_size(?PREFACE) ->
    {ok, Data} = gen_tcp:recv(Sock, 0, 5000),
    read_preface(Sock, <<Buf/binary, Data/binary>>);
read_preface(_Sock, Buf) ->
    Size = byte_size(?PREFACE),
    <<Preface:Size/binary, Rest/binary>> = Buf,
    ?PREFACE = Preface,
    Rest.

loop(Sock, Buf, Mode, TestPid) ->
    receive stop -> gen_tcp:close(Sock) after 0 -> ok end,
    case h2_frame:decode(Buf) of
        {ok, Frame, Rest} ->
            Mode1 = handle_frame(Sock, Frame, Mode, TestPid),
            loop(Sock, Rest, Mode1, TestPid);
        {more, _} ->
            case gen_tcp:recv(Sock, 0, 100) of
                {ok, Data} ->
                    loop(Sock, <<Buf/binary, Data/binary>>, Mode, TestPid);
                {error, timeout} ->
                    loop(Sock, Buf, Mode, TestPid);
                {error, _} ->
                    gen_tcp:close(Sock)
            end;
        {error, _} ->
            gen_tcp:close(Sock)
    end.

handle_frame(Sock, {settings, _}, Mode, _TestPid) ->
    ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:settings_ack())),
    Mode;
handle_frame(Sock, Frame, goaway, _TestPid) when element(1, Frame) =:= headers ->
    ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:goaway(0, no_error, <<>>))),
    plain;
handle_frame(_Sock, {rst_stream, StreamId, Code}, Mode, TestPid) ->
    TestPid ! {rst_stream, StreamId, Code},
    Mode;
handle_frame(_Sock, _Frame, Mode, _TestPid) ->
    Mode.

-endif.
