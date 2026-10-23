%% @doc The connection receive window follows `connection_window_size'. A raw
%% gen_tcp h2c server built on h2_frame answers each request with a body sent
%% in 16 KB DATA frames, only while both the connection and the stream send
%% windows allow it, and counts how often it has to wait for a WINDOW_UPDATE.
-module(h2_conn_window_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(DEFAULT_WINDOW, 65535).
-define(CHUNK, 16384).
-define(MB, (1024 * 1024)).
-define(SETTINGS_INITIAL_WINDOW_SIZE, 16#4).

conn_window_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"default options keep the 65535 connection window",
       {timeout, 30, fun default_window/0}},
      {"a large window is granted right after SETTINGS",
       {timeout, 30, fun initial_grant/0}},
      {"a large window delivers the body without waits",
       {timeout, 30, fun no_waits/0}},
      {"the window is refilled to the target across requests",
       {timeout, 60, fun refill_to_target/0}},
      {"invalid connection_window_size values are rejected",
       fun invalid_values/0},
      {"a server with default options grants nothing on stream 0",
       {timeout, 30, fun server_default_window/0}},
      {"a server grants connection_window_size after its SETTINGS",
       {timeout, 30, fun server_grant/0}}]}.

large_opts() ->
    #{transport => tcp,
      connection_window_size => 16 * ?MB,
      settings => #{initial_window_size => 16 * ?MB}}.

default_window() ->
    start_case(),
    {Port, Server} = start_server(?MB, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    {Waits, PreGrant} = fetch(Conn, Port, ?MB),
    ?assertEqual(0, PreGrant),
    ?assert(Waits > 0),
    cleanup(Conn, Server).

initial_grant() ->
    start_case(),
    {Port, Server} = start_server(?MB, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, large_opts()),
    ok = h2:wait_connected(Conn),
    {_Waits, PreGrant} = fetch(Conn, Port, ?MB),
    ?assertEqual(16 * ?MB - ?DEFAULT_WINDOW, PreGrant),
    cleanup(Conn, Server).

no_waits() ->
    start_case(),
    {Port, Server} = start_server(4 * ?MB, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, large_opts()),
    ok = h2:wait_connected(Conn),
    ?assertMatch({0, _}, fetch(Conn, Port, 4 * ?MB)),
    cleanup(Conn, Server).

%% Two 12 MB bodies use 24 MB of a 16 MB window, so the second one only
%% goes through without waits if the first was refilled to 16 MB.
refill_to_target() ->
    start_case(),
    {Port, Server} = start_server(12 * ?MB, self()),
    {ok, Conn} = h2:connect("127.0.0.1", Port, large_opts()),
    ok = h2:wait_connected(Conn),
    ?assertMatch({0, _}, fetch(Conn, Port, 12 * ?MB)),
    ?assertMatch({0, _}, fetch(Conn, Port, 12 * ?MB)),
    cleanup(Conn, Server).

invalid_values() ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    try
        lists:foreach(
          fun(V) ->
                  ?assertEqual({error, {invalid_option, {connection_window_size, V}}},
                               h2_connection:start_link(client, LSock,
                                                        #{connection_window_size => V}))
          end,
          [0, 65534, 2147483648, big])
    after
        gen_tcp:close(LSock)
    end.

server_default_window() ->
    ?assertEqual(0, server_grant(#{})).

server_grant() ->
    ?assertEqual(16 * ?MB - ?DEFAULT_WINDOW,
                 server_grant(#{connection_window_size => 16 * ?MB})).

%% Start an h2 server, open the connection from a raw client and return the
%% stream-0 increments the server sends before it acks our PING. The grant
%% is sent at activation, before the server reads anything, so it always
%% precedes the PING ack.
server_grant(Opts) ->
    Handler = fun(Conn, StreamId, _Method, _Path, _Headers) ->
                      h2:send_response(Conn, StreamId, 200, [])
              end,
    {ok, Ref} = h2:start_server(0, Opts#{transport => tcp, handler => Handler}),
    try
        {ok, Sock} = gen_tcp:connect("127.0.0.1", h2:server_port(Ref),
                                     [binary, {active, false}, {packet, raw}], 5000),
        Ping = <<"connwin!">>,
        ok = gen_tcp:send(Sock, [?PREFACE,
                                 h2_frame:encode(h2_frame:settings([])),
                                 h2_frame:encode(h2_frame:ping(Ping))]),
        try
            sum_grants(Sock, <<>>, Ping, 0)
        after
            gen_tcp:close(Sock)
        end
    after
        h2:stop_server(Ref)
    end.

sum_grants(Sock, Buf, Ping, Acc) ->
    case h2_frame:decode(Buf) of
        {ok, {ping_ack, Ping}, _Rest} ->
            Acc;
        {ok, {settings, _}, Rest} ->
            ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:settings_ack())),
            sum_grants(Sock, Rest, Ping, Acc);
        {ok, {window_update, 0, Inc}, Rest} ->
            sum_grants(Sock, Rest, Ping, Acc + Inc);
        {ok, _Frame, Rest} ->
            sum_grants(Sock, Rest, Ping, Acc);
        {more, _} ->
            {ok, Data} = gen_tcp:recv(Sock, 0, 5000),
            sum_grants(Sock, <<Buf/binary, Data/binary>>, Ping, Acc)
    end.

%% Send one GET, read the whole body, and return what the server measured.
fetch(Conn, Port, Size) ->
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, authority(Port)}]),
    receive
        {h2, Conn, {response, StreamId, 200, _}} -> ok
    after 5000 ->
        error(no_response)
    end,
    ?assertEqual(Size, read_body(Conn, StreamId, 0)),
    receive
        {done, StreamId, Waits, PreGrant} -> {Waits, PreGrant}
    after 5000 ->
        error(server_not_done)
    end.

read_body(Conn, StreamId, Acc) ->
    receive
        {h2, Conn, {data, StreamId, Data, true}} -> Acc + byte_size(Data);
        {h2, Conn, {data, StreamId, Data, false}} -> read_body(Conn, StreamId, Acc + byte_size(Data))
    after 10000 ->
        error({body_stalled, Acc})
    end.

%% Cases in one fixture run in the same process, so a failed case must not
%% leave messages behind for the next one.
start_case() ->
    process_flag(trap_exit, true),
    flush().

cleanup(Conn, Server) ->
    try h2:close(Conn) catch exit:_ -> ok end,
    Server ! stop,
    receive {'EXIT', Server, _} -> ok after 5000 -> error(server_still_up) end,
    flush().

flush() ->
    receive _ -> flush() after 0 -> ok end.

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

%% ---------------------------------------------------------------------------
%% Raw h2c server. Answers each HEADERS with `:status 200' and BodySize bytes,
%% then reports {done, StreamId, Waits, PreGrant} to the test process. PreGrant
%% is the sum of stream-0 WINDOW_UPDATE increments seen before the first
%% HEADERS.
%% ---------------------------------------------------------------------------

start_server(BodySize, TestPid) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {packet, raw},
                                     {ip, {127, 0, 0, 1}}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Pid = spawn_link(fun() -> serve(LSock, BodySize, TestPid) end),
    {Port, Pid}.

serve(LSock, BodySize, TestPid) ->
    {ok, Sock} = gen_tcp:accept(LSock, 5000),
    Rest = read_preface(Sock, <<>>),
    ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:settings([]))),
    loop(#{sock => Sock, buf => Rest, test => TestPid, body_size => BodySize,
           conn_win => ?DEFAULT_WINDOW, init_win => ?DEFAULT_WINDOW,
           streams => #{}, pre_grant => 0, headers_seen => false,
           hpack => h2_hpack:new_context()}).

read_preface(Sock, Buf) when byte_size(Buf) < byte_size(?PREFACE) ->
    {ok, Data} = gen_tcp:recv(Sock, 0, 5000),
    read_preface(Sock, <<Buf/binary, Data/binary>>);
read_preface(_Sock, Buf) ->
    Size = byte_size(?PREFACE),
    <<Preface:Size/binary, Rest/binary>> = Buf,
    ?PREFACE = Preface,
    Rest.

loop(#{sock := Sock} = S) ->
    receive stop -> gen_tcp:close(Sock) after 0 -> ok end,
    case next_frame(S) of
        {ok, Frame, S1} when element(1, Frame) =:= headers ->
            loop(respond(element(2, Frame), S1));
        {ok, Frame, S1} ->
            loop(apply_frame(Frame, S1));
        {timeout, S1} ->
            loop(S1);
        closed ->
            gen_tcp:close(Sock)
    end.

next_frame(#{sock := Sock, buf := Buf} = S) ->
    case h2_frame:decode(Buf) of
        {ok, Frame, Rest} ->
            {ok, Frame, S#{buf := Rest}};
        {more, _} ->
            case gen_tcp:recv(Sock, 0, 100) of
                {ok, Data} -> next_frame(S#{buf := <<Buf/binary, Data/binary>>});
                {error, timeout} -> {timeout, S};
                {error, _} -> closed
            end;
        {error, _} ->
            closed
    end.

apply_frame({settings, Settings}, #{sock := Sock, init_win := Init} = S) ->
    ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:settings_ack())),
    S#{init_win := proplists:get_value(?SETTINGS_INITIAL_WINDOW_SIZE, Settings, Init)};
apply_frame({window_update, 0, Inc}, #{conn_win := Win, pre_grant := Pre} = S) ->
    case maps:get(headers_seen, S) of
        false -> S#{conn_win := Win + Inc, pre_grant := Pre + Inc};
        true -> S#{conn_win := Win + Inc}
    end;
apply_frame({window_update, StreamId, Inc}, #{streams := Streams} = S) ->
    case Streams of
        #{StreamId := Win} -> S#{streams := Streams#{StreamId := Win + Inc}};
        _ -> S
    end;
apply_frame(_Frame, S) ->
    S.

respond(StreamId, #{sock := Sock, hpack := Ctx, init_win := Init,
                    streams := Streams, body_size := Size, test := TestPid} = S) ->
    {Block, Ctx1} = h2_hpack:encode([{<<":status">>, <<"200">>}], Ctx),
    ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:headers(StreamId, Block, false))),
    S1 = S#{hpack := Ctx1, headers_seen := true, streams := Streams#{StreamId => Init}},
    {Waits, S2} = send_body(StreamId, Size, 0, S1),
    TestPid ! {done, StreamId, Waits, maps:get(pre_grant, S2)},
    S2.

send_body(_StreamId, 0, Waits, S) ->
    {Waits, S};
send_body(StreamId, Left, Waits, #{sock := Sock, conn_win := ConnWin,
                                    streams := Streams} = S) ->
    N = min(?CHUNK, Left),
    StreamWin = maps:get(StreamId, Streams),
    case N =< ConnWin andalso N =< StreamWin of
        true ->
            Frame = h2_frame:data(StreamId, <<0:N/unit:8>>, N =:= Left),
            ok = gen_tcp:send(Sock, h2_frame:encode(Frame)),
            send_body(StreamId, Left - N,  Waits,
                      S#{conn_win := ConnWin - N,
                         streams := Streams#{StreamId := StreamWin - N}});
        false ->
            send_body(StreamId, Left, Waits + 1, wait_window(StreamId, N, S))
    end.

%% Read frames until both windows have room for N bytes.
wait_window(StreamId, N, S) ->
    case next_frame(S) of
        {ok, Frame, S1} ->
            #{conn_win := ConnWin, streams := #{StreamId := StreamWin}} = S2 =
                apply_frame(Frame, S1),
            case N =< ConnWin andalso N =< StreamWin of
                true -> S2;
                false -> wait_window(StreamId, N, S2)
            end;
        {timeout, S1} ->
            wait_window(StreamId, N, S1);
        closed ->
            exit(closed_while_waiting)
    end.

-endif.
