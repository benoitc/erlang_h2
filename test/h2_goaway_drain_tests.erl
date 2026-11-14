%% @doc Graceful GOAWAY (RFC 9113 §6.8): after `h2:goaway/1' the streams already
%% open finish before the connection closes, new streams above the final
%% GOAWAY's last stream id are discarded with HPACK and flow-control state kept
%% in step, and the last stream id is never increased. Driven from a raw h2c
%% client built on gen_tcp + h2_frame/h2_hpack so the wire is checked exactly.
-module(h2_goaway_drain_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(MAX_ID, 16#7fffffff).

goaway_drain_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"open stream completes after the final GOAWAY",
       {timeout, 30, fun in_flight_completes/0}},
      {"no open stream: closes right after the final GOAWAY",
       {timeout, 30, fun idle_closes_at_once/0}},
      {"stream opened between the two GOAWAYs is served",
       {timeout, 30, fun stream_between_goaways/0}},
      {"peer GOAWAY during the drain does not drop open streams",
       {timeout, 30, fun peer_goaway_during_drain/0}},
      {"HEADERS above the last id is discarded, HPACK stays in step",
       {timeout, 30, fun headers_above_discarded/0}},
      {"DATA above the last id is discarded, connection window refilled",
       {timeout, 30, fun data_above_discarded/0}},
      {"connection error while draining keeps the last id",
       {timeout, 30, fun error_keeps_last_id/0}},
      {"a repeated goaway sends no extra GOAWAY",
       {timeout, 30, fun repeat_goaway/0}},
      {"goaway_timeout bounds the drain",
       {timeout, 30, fun timeout_bounds_drain/0}},
      {"per-call timeout bounds the drain",
       {timeout, 30, fun call_timeout_bounds_drain/0}},
      {"h2 client: own request completes after its GOAWAY",
       {timeout, 30, fun client_goaway_drains/0}}]}.

%% ---------------------------------------------------------------------------
%% Cases
%% ---------------------------------------------------------------------------

in_flight_completes() ->
    {Ref, Sock, Ctx} = connect(held_handler(), #{}),
    try
        _ = request(Sock, 1, Ctx, true),
        {Conn, H1} = wait_request(1),
        ok = h2:goaway(Conn),
        {Frames1, open} = read_until(Sock, fun is_final_goaway/1, 2000),
        ?assertEqual([{goaway, ?MAX_ID, 0}, {goaway, 1, 0}], goaways(Frames1)),
        %% The connection outlives the old 100 ms drain.
        timer:sleep(300),
        H1 ! {reply, <<"done">>},
        {Frames2, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assertMatch([{headers, 1, _}, {data, 1, <<"done">>, true}],
                     stream_frames(1, Frames2)),
        ?assertEqual([], goaways(Frames2)),
        ?assertEqual(ok, wait_reply_result(H1))
    after
        close(Ref, Sock)
    end.

idle_closes_at_once() ->
    {Ref, Sock, Ctx} = connect(held_handler(), #{}),
    try
        _ = request(Sock, 1, Ctx, true),
        {Conn, H1} = wait_request(1),
        H1 ! {reply, <<"x">>},
        {_, open} = read_until(Sock, fun(F) -> is_data_fin(1, F) end, 2000),
        T0 = now_ms(),
        ok = h2:goaway(Conn),
        {Frames, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assertEqual([{goaway, ?MAX_ID, 0}, {goaway, 1, 0}], goaways(Frames)),
        ?assert(now_ms() - T0 < 1000)
    after
        close(Ref, Sock)
    end.

stream_between_goaways() ->
    {Ref, Sock, Ctx} = connect(held_handler(), #{}),
    try
        Ctx1 = request(Sock, 1, Ctx, true),
        {Conn, H1} = wait_request(1),
        ok = h2:goaway(Conn),
        {_, open} = read_until(Sock, fun(F) -> F =:= {goaway, ?MAX_ID, 0, <<>>} end, 2000),
        %% RFC 9113 §6.8: requests sent before the client saw the warning
        %% GOAWAY are still accepted and covered by the final one.
        _ = request(Sock, 3, Ctx1, true),
        {Conn, H3} = wait_request(3),
        {Frames1, open} = read_until(Sock, fun is_final_goaway/1, 2000),
        ?assertEqual([{goaway, 3, 0}], goaways(Frames1)),
        H1 ! {reply, <<"one">>},
        H3 ! {reply, <<"three">>},
        {Frames2, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assertMatch([_, {data, 1, <<"one">>, true}], stream_frames(1, Frames2)),
        ?assertMatch([_, {data, 3, <<"three">>, true}], stream_frames(3, Frames2))
    after
        close(Ref, Sock)
    end.

peer_goaway_during_drain() ->
    {Ref, Sock, Ctx} = connect(held_handler(), #{}),
    try
        _ = request(Sock, 1, Ctx, true),
        {Conn, H1} = wait_request(1),
        ok = h2:goaway(Conn),
        {_, open} = read_until(Sock, fun(F) -> F =:= {goaway, ?MAX_ID, 0, <<>>} end, 2000),
        ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:goaway(0, no_error, <<>>))),
        timer:sleep(200),
        H1 ! {reply, <<"done">>},
        {Frames, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assertMatch([_, {data, 1, <<"done">>, true}], stream_frames(1, Frames))
    after
        close(Ref, Sock)
    end.

headers_above_discarded() ->
    {Ref, Sock, Ctx} = connect(trailers_handler(), #{}),
    try
        %% Stream 1 keeps its request open, so trailers can follow later.
        Ctx1 = request(Sock, 1, Ctx, false),
        {Conn, _H1} = wait_request(1),
        ok = h2:goaway(Conn),
        {_, open} = read_until(Sock, fun is_final_goaway/1, 2000),
        %% Stream 3 is above the last id. Its block adds `x-sync' to the
        %% HPACK dynamic table; the trailers on stream 1 then reference that
        %% entry by index, so they only decode if stream 3 was decoded too.
        {Block3, Ctx2} = h2_hpack:encode(req_headers() ++ [{<<"x-sync">>, <<"abc123">>}], Ctx1),
        {Trailers, _} = h2_hpack:encode([{<<"x-sync">>, <<"abc123">>}], Ctx2),
        ?assert(byte_size(Trailers) =< 2),
        ok = gen_tcp:send(Sock, [h2_frame:encode(h2_frame:headers(3, Block3, true)),
                                 h2_frame:encode(h2_frame:headers(1, Trailers, true))]),
        {Frames, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assertEqual([], [F || {rst_stream, _, _} = F <- Frames]),
        ?assertEqual([], goaways(Frames)),
        [{headers, 1, Resp}, {data, 1, <<"abc123">>, true}] = stream_frames(1, Frames),
        ?assertMatch({ok, [{<<":status">>, <<"200">>} | _], _},
                     h2_hpack:decode(Resp, h2_hpack:new_context())),
        receive {request, _, 3} -> error(discarded_stream_reached_handler)
        after 100 -> ok end
    after
        close(Ref, Sock)
    end.

data_above_discarded() ->
    {Ref, Sock, Ctx} = connect(held_handler(), #{}),
    try
        Ctx1 = request(Sock, 1, Ctx, true),
        {Conn, H1} = wait_request(1),
        ok = h2:goaway(Conn),
        {_, open} = read_until(Sock, fun is_final_goaway/1, 2000),
        {Block3, _} = h2_hpack:encode(req_headers(), Ctx1),
        Chunk = binary:copy(<<"z">>, 16000),
        ok = gen_tcp:send(Sock, [h2_frame:encode(h2_frame:headers(3, Block3, false)),
                                 [h2_frame:encode(h2_frame:data(3, Chunk, false))
                                  || _ <- lists:seq(1, 3)]]),
        %% 48000 bytes is past half the 65535 window: the server must count
        %% them and refill the connection window, not treat stream 3 as idle.
        {Frames1, open} = read_until(Sock, fun(F) -> element(1, F) =:= window_update end, 2000),
        ?assertMatch([{window_update, 0, _}], [F || {window_update, _, _} = F <- Frames1]),
        H1 ! {reply, <<"done">>},
        {Frames2, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assertEqual([], goaways(Frames1 ++ Frames2)),
        ?assertEqual([], [F || {rst_stream, _, _} = F <- Frames1 ++ Frames2]),
        ?assertMatch([_, {data, 1, <<"done">>, true}], stream_frames(1, Frames2))
    after
        close(Ref, Sock)
    end.

error_keeps_last_id() ->
    {Ref, Sock, Ctx} = connect(held_handler(), #{}),
    try
        Ctx1 = request(Sock, 1, Ctx, true),
        {Conn, _H1} = wait_request(1),
        ok = h2:goaway(Conn),
        {_, open} = read_until(Sock, fun is_final_goaway/1, 2000),
        {Block3, _} = h2_hpack:encode(req_headers(), Ctx1),
        %% A discarded stream 3, then a connection error (WINDOW_UPDATE 0 on
        %% stream 0). Its GOAWAY must not raise the last id above 1.
        ok = gen_tcp:send(Sock, [h2_frame:encode(h2_frame:headers(3, Block3, true)),
                                 <<4:24, 8:8, 0:8, 0:1, 0:31, 0:32>>]),
        {Frames, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assertEqual([{goaway, 1, 1}], goaways(Frames))
    after
        close(Ref, Sock)
    end.

repeat_goaway() ->
    {Ref, Sock, Ctx} = connect(held_handler(), #{}),
    try
        _ = request(Sock, 1, Ctx, true),
        {Conn, H1} = wait_request(1),
        ok = h2:goaway(Conn),
        ok = h2:goaway(Conn),
        {Frames1, open} = read_until(Sock, fun is_final_goaway/1, 2000),
        ok = h2:goaway(Conn),
        H1 ! {reply, <<"done">>},
        {Frames2, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assertEqual([{goaway, ?MAX_ID, 0}, {goaway, 1, 0}], goaways(Frames1 ++ Frames2))
    after
        close(Ref, Sock)
    end.

timeout_bounds_drain() ->
    {Ref, Sock, Ctx} = connect(watch_handler(), #{goaway_timeout => 300}),
    try
        _ = request(Sock, 1, Ctx, false),
        {Conn, _H1} = wait_request(1),
        ok = h2:goaway(Conn),
        {_, open} = read_until(Sock, fun is_final_goaway/1, 2000),
        T0 = now_ms(),
        {_, closed} = read_until(Sock, fun(_) -> false end, 3000),
        Elapsed = now_ms() - T0,
        ?assert(Elapsed >= 250 andalso Elapsed < 1500),
        ?assertEqual(goaway_timeout, wait_handler_closed())
    after
        close(Ref, Sock)
    end.

call_timeout_bounds_drain() ->
    {Ref, Sock, Ctx} = connect(watch_handler(), #{}),
    try
        _ = request(Sock, 1, Ctx, false),
        {Conn, _H1} = wait_request(1),
        ok = h2:goaway(Conn, #{timeout => 200}),
        {_, open} = read_until(Sock, fun is_final_goaway/1, 2000),
        T0 = now_ms(),
        {_, closed} = read_until(Sock, fun(_) -> false end, 3000),
        ?assert(now_ms() - T0 < 1500),
        ?assertEqual(goaway_timeout, wait_handler_closed())
    after
        close(Ref, Sock)
    end.

client_goaway_drains() ->
    process_flag(trap_exit, true),
    Test = self(),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
                      Test ! {request, self(), Sid},
                      receive go -> ok end,
                      ok = h2:send_response(Conn, Sid, 200, []),
                      ok = h2:send_data(Conn, Sid, <<"late">>, true)
              end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler}),
    {ok, Client} = h2:connect("127.0.0.1", h2:server_port(Ref), #{transport => tcp}),
    try
        ok = h2:wait_connected(Client),
        {ok, Sid} = h2:request(Client, <<"GET">>, <<"/">>, [{<<"host">>, <<"x">>}]),
        H = receive {request, Pid, Sid} -> Pid after 5000 -> error(no_request) end,
        ok = h2:goaway(Client),
        timer:sleep(300),
        H ! go,
        ?assertEqual(<<"late">>,
                     receive {h2, Client, {data, Sid, D, true}} -> D
                     after 3000 -> error(no_data) end),
        ?assertEqual(goaway_drained,
                     receive {h2, Client, {closed, R}} -> R
                     after 3000 -> error(no_closed) end)
    after
        try h2:close(Client) catch _:_ -> ok end,
        h2:stop_server(Ref),
        flush()
    end.

%% ---------------------------------------------------------------------------
%% Handlers
%% ---------------------------------------------------------------------------

%% Reports the request, then answers when told to and reports the result.
held_handler() ->
    Test = self(),
    fun(Conn, Sid, _M, _P, _H) ->
            Test ! {request, {Conn, self()}, Sid},
            receive {reply, Body} -> ok end,
            R1 = h2:send_response(Conn, Sid, 200, []),
            R2 = h2:send_data(Conn, Sid, Body, true),
            Test ! {reply_result, self(), {R1, R2}}
    end.

%% Waits for the request trailers and echoes the `x-sync' value as the body.
trailers_handler() ->
    Test = self(),
    fun(Conn, Sid, _M, _P, _H) ->
            ok = h2:set_stream_handler(Conn, Sid, self()),
            Test ! {request, {Conn, self()}, Sid},
            Value = receive
                        {h2, Conn, {trailers, Sid, T}} ->
                            proplists:get_value(<<"x-sync">>, T)
                    after 5000 -> <<"none">>
                    end,
            ok = h2:send_response(Conn, Sid, 200, []),
            ok = h2:send_data(Conn, Sid, Value, true)
    end.

%% Never answers; reports the `closed' reason its stream handler gets.
watch_handler() ->
    Test = self(),
    fun(Conn, Sid, _M, _P, _H) ->
            ok = h2:set_stream_handler(Conn, Sid, self()),
            Test ! {request, {Conn, self()}, Sid},
            watch(Conn, Test)
    end.

watch(Conn, Test) ->
    receive
        {h2, Conn, {closed, Reason}} -> Test ! {handler_closed, Reason};
        _ -> watch(Conn, Test)
    after 5000 -> ok
    end.

%% ---------------------------------------------------------------------------
%% Raw client
%% ---------------------------------------------------------------------------

connect(Handler, Opts) ->
    {ok, Ref} = h2:start_server(0, Opts#{transport => tcp, handler => Handler}),
    {ok, Sock} = gen_tcp:connect("127.0.0.1", h2:server_port(Ref),
                                 [binary, {active, false}, {packet, raw}], 5000),
    ok = gen_tcp:send(Sock, [?PREFACE,
                             h2_frame:encode(h2_frame:settings([])),
                             h2_frame:encode(h2_frame:settings_ack())]),
    {Ref, Sock, h2_hpack:new_context()}.

req_headers() ->
    [{<<":method">>, <<"POST">>}, {<<":path">>, <<"/">>},
     {<<":scheme">>, <<"http">>}, {<<":authority">>, <<"x">>}].

request(Sock, Sid, Ctx, EndStream) ->
    {Block, Ctx1} = h2_hpack:encode(req_headers(), Ctx),
    ok = gen_tcp:send(Sock, h2_frame:encode(h2_frame:headers(Sid, Block, EndStream))),
    Ctx1.

wait_request(Sid) ->
    receive {request, {Conn, Pid}, Sid} -> {Conn, Pid}
    after 5000 -> error({no_request, Sid})
    end.

wait_reply_result(Pid) ->
    receive {reply_result, Pid, {ok, ok}} -> ok;
            {reply_result, Pid, Other} -> Other
    after 3000 -> error(no_reply_result)
    end.

wait_handler_closed() ->
    receive {handler_closed, Reason} -> Reason
    after 3000 -> error(no_handler_closed)
    end.

%% Read frames until Stop(Frame) is true (`open') or the socket closes
%% (`closed'). Frames come back in arrival order; SETTINGS / PING are dropped.
read_until(Sock, Stop, Timeout) ->
    read_until(Sock, Stop, <<>>, [], now_ms() + Timeout).

read_until(Sock, Stop, Buf, Acc, Deadline) ->
    case h2_frame:decode(Buf) of
        {ok, Frame, Rest} ->
            Acc1 = case element(1, Frame) of
                       settings -> Acc;
                       settings_ack -> Acc;
                       _ -> [Frame | Acc]
                   end,
            case Stop(Frame) of
                true -> {lists:reverse(Acc1), open};
                false -> read_until(Sock, Stop, Rest, Acc1, Deadline)
            end;
        {more, _} ->
            T = Deadline - now_ms(),
            T > 0 orelse error({timeout, lists:reverse(Acc)}),
            case gen_tcp:recv(Sock, 0, T) of
                {ok, Data} -> read_until(Sock, Stop, <<Buf/binary, Data/binary>>, Acc, Deadline);
                {error, closed} -> {lists:reverse(Acc), closed};
                {error, timeout} -> error({timeout, lists:reverse(Acc)})
            end
    end.

is_final_goaway({goaway, Last, _, _}) -> Last =/= ?MAX_ID;
is_final_goaway(_) -> false.

is_data_fin(Sid, {data, Sid, _, true}) -> true;
is_data_fin(Sid, {data, Sid, _, true, _}) -> true;
is_data_fin(_, _) -> false.

goaways(Frames) ->
    [{goaway, Last, code(Code)} || {goaway, Last, Code, _} <- Frames].

code(Code) when is_integer(Code) -> Code;
code(Code) -> h2_error:code(Code).

%% HEADERS and DATA frames of one stream, normalised for matching.
stream_frames(Sid, Frames) ->
    lists:filtermap(
      fun({headers, S, Block, _End, _EndH}) when S =:= Sid -> {true, {headers, S, Block}};
         ({headers, S, Block, _End, _EndH, _P}) when S =:= Sid -> {true, {headers, S, Block}};
         ({data, S, D, End}) when S =:= Sid -> {true, {data, S, D, End}};
         ({data, S, D, End, _Fc}) when S =:= Sid -> {true, {data, S, D, End}};
         (_) -> false
      end, Frames).

now_ms() -> erlang:monotonic_time(millisecond).

close(Ref, Sock) ->
    _ = gen_tcp:close(Sock),
    h2:stop_server(Ref),
    flush().

flush() ->
    receive _ -> flush() after 0 -> ok end.

-endif.
