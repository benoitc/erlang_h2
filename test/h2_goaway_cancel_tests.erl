%% @doc Existing streams stay valid after a GOAWAY in either direction (RFC
%% 9113 6.8): they can be reset and finished with trailers, while new streams
%% are refused. A raw gen_tcp h2c server built on h2_frame reports every
%% RST_STREAM and HEADERS frame it receives to the test process.
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
       {timeout, 30, fun cancel_after_own_goaway/0}},
      {"a new request after a received GOAWAY is refused",
       {timeout, 30, fun request_after_received_goaway/0}},
      {"send trailers on an open stream after a received GOAWAY",
       {timeout, 30, fun trailers_after_received_goaway/0}},
      {"send trailers on an open stream after sending our own GOAWAY",
       {timeout, 30, fun trailers_after_own_goaway/0}}]}.

refused_stream_cancel() ->
    start_case(),
    {Port, Server} = start_server(goaway, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, headers(Port)),
    wait_goaway(Conn),
    ?assertEqual(ok, h2:cancel(Conn, StreamId)),
    ?assertEqual(?CANCEL, wait_rst_stream(StreamId)),
    cleanup(Conn, Server).

cancel_after_own_goaway() ->
    start_case(),
    {Port, Server} = start_server(plain, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, headers(Port)),
    ok = h2:goaway(Conn),
    ?assertEqual(ok, h2:cancel(Conn, StreamId)),
    ?assertEqual(?CANCEL, wait_rst_stream(StreamId)),
    cleanup(Conn, Server).

request_after_received_goaway() ->
    start_case(),
    {Port, Server} = start_server(goaway, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    {ok, _StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, headers(Port)),
    wait_goaway(Conn),
    ?assertEqual({error, goaway_received},
                 h2:request(Conn, <<"GET">>, <<"/">>, headers(Port))),
    ?assertEqual({error, goaway_received},
                 h2:request(Conn, pseudo_headers(Port), #{end_stream => false})),
    cleanup(Conn, Server).

trailers_after_received_goaway() ->
    start_case(),
    {Port, Server} = start_server(goaway, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    {ok, StreamId} = h2:request(Conn, pseudo_headers(Port), #{end_stream => false}),
    false = wait_headers(StreamId),
    wait_goaway(Conn),
    ?assertEqual(ok, h2:send_trailers(Conn, StreamId, [{<<"grpc-status">>, <<"0">>}])),
    ?assertEqual(true, wait_headers(StreamId)),
    cleanup(Conn, Server).

trailers_after_own_goaway() ->
    start_case(),
    {Port, Server} = start_server(plain, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    {ok, StreamId} = h2:request(Conn, pseudo_headers(Port), #{end_stream => false}),
    false = wait_headers(StreamId),
    ok = h2:goaway(Conn),
    ?assertEqual(ok, h2:send_trailers(Conn, StreamId, [{<<"grpc-status">>, <<"0">>}])),
    ?assertEqual(true, wait_headers(StreamId)),
    cleanup(Conn, Server).

%% Cases in one fixture run in the same process, so a failed case must not
%% leave frames or EXIT messages behind for the next one.
start_case() ->
    process_flag(trap_exit, true),
    flush().

wait_goaway(Conn) ->
    receive
        {h2, Conn, {goaway, 0, no_error}} -> ok
    after 5000 ->
        error(no_goaway)
    end.

wait_rst_stream(StreamId) ->
    receive
        {rst_stream, StreamId, Code} -> Code
    after 5000 ->
        error(no_rst_stream)
    end.

wait_headers(StreamId) ->
    receive
        {headers, StreamId, EndStream} -> EndStream
    after 5000 ->
        error(no_headers)
    end.

cleanup(Conn, Server) ->
    try h2:close(Conn) catch exit:_ -> ok end,
    Server ! stop,
    receive {'EXIT', Server, _} -> ok after 5000 -> error(server_still_up) end,
    flush().

flush() ->
    receive _ -> flush() after 0 -> ok end.

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

headers(Port) ->
    [{<<"host">>, authority(Port)}].

pseudo_headers(Port) ->
    [{<<":method">>,    <<"POST">>},
     {<<":path">>,      <<"/">>},
     {<<":scheme">>,    <<"http">>},
     {<<":authority">>, authority(Port)}].

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
handle_frame(Sock, Frame, Mode, TestPid) when element(1, Frame) =:= headers ->
    TestPid ! {headers, element(2, Frame), element(4, Frame)},
    case Mode of
        goaway ->
            ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:goaway(0, no_error, <<>>))),
            plain;
        plain ->
            plain
    end;
handle_frame(_Sock, {rst_stream, StreamId, Code}, Mode, TestPid) ->
    TestPid ! {rst_stream, StreamId, Code},
    Mode;
handle_frame(_Sock, _Frame, Mode, _TestPid) ->
    Mode.

-endif.
