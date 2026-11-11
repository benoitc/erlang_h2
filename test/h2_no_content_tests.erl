%% @doc Responses with no content (RFC 9113 §8.1, RFC 9110 §6.4.1, §8.6,
%% §9.3.2, §15.2): a final response to HEAD, and any 204 or 304.
%%
%% Server: such a response is one HEADERS block (plus CONTINUATION) carrying
%% END_STREAM, never followed by DATA or trailers. A body or trailers offered
%% anyway is dropped and the call returns ok. Content-Length is removed from
%% 1xx and 204. A 1xx never ends the stream, even on HEAD.
%%
%% Client: DATA that does not match the declared length, or DATA after a
%% no-content response, is rejected and never delivered as content.
%%
%% Every case drives a raw peer over gen_tcp and asserts the exact frames.
-module(h2_no_content_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).

-define(DATA, 0).
-define(HEADERS, 1).
-define(RST_STREAM, 3).
-define(SETTINGS, 4).
-define(GOAWAY, 7).
-define(WINDOW_UPDATE, 8).
-define(CONTINUATION, 9).

-define(END_STREAM, 16#1).
-define(END_HEADERS, 16#4).

-define(PROTOCOL_ERROR, 1).
-define(STREAM_CLOSED, 5).

no_content_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"204, 304 and HEAD end on HEADERS, with or without a body offered",
       {timeout, 30, fun ends_on_headers/0}},
      {"a streamed body and trailers after a no-content response are dropped",
       {timeout, 30, fun streamed_body_dropped/0}},
      {"a no-content response split over CONTINUATION still ends on HEADERS",
       {timeout, 30, fun continuation/0}},
      {"content-length is removed from 1xx and 204, kept on 304 and HEAD",
       {timeout, 30, fun content_length/0}},
      {"1xx precede the final response and never end the stream",
       {timeout, 30, fun informational/0}},
      {"misuse of 1xx is refused",
       {timeout, 30, fun informational_misuse/0}},
      {"after a 204 the stream is closed and no window was charged",
       {timeout, 30, fun connection_stays_healthy/0}},
      {"an early 204 does not break the incoming request body",
       {timeout, 30, fun early_204_upload/0}},
      {"send_data still succeeds once the 204 stream record is evicted",
       {timeout, 60, fun evicted_record/0}},
      {"client: content-length mismatch is a stream PROTOCOL_ERROR",
       {timeout, 30, fun client_length_mismatch/0}},
      {"client: DATA after a 204 that ended the stream is STREAM_CLOSED",
       {timeout, 30, fun client_data_after_204/0}},
      {"client: 304 and HEAD without END_STREAM are rejected",
       {timeout, 30, fun client_no_end_stream/0}},
      {"client: a 304 ending on HEADERS is complete at once",
       {timeout, 30, fun client_304_complete/0}}]}.

%% ---------------------------------------------------------------------------
%% Server sending
%% ---------------------------------------------------------------------------

ends_on_headers() ->
    Test = self(),
    Handler = fun(Conn, Sid, _M, Path, _H) ->
        R = case Path of
            <<"/send/", S/binary>> ->
                [h2:send_response(Conn, Sid, binary_to_integer(S), []),
                 h2:send_data(Conn, Sid, <<"body">>, true)];
            <<"/respond/", S/binary>> ->
                [h2:respond(Conn, Sid, binary_to_integer(S), [], <<"body">>)]
        end,
        Test ! {result, Sid, R}
    end,
    with_raw_client(#{}, Handler, fun(Raw0) ->
        Cases = [{<<"GET">>, Api, Status}
                 || Api <- [<<"send">>, <<"respond">>],
                    Status <- [<<"204">>, <<"304">>]]
                ++ [{<<"HEAD">>, Api, <<"200">>}
                    || Api <- [<<"send">>, <<"respond">>]],
        lists:foldl(fun({Method, Api, Status}, Raw) ->
            {Sid, Raw1} = request(Raw, Method, <<"/", Api/binary, "/", Status/binary>>),
            {Frames, Raw2} = stream_frames(Raw1, Sid),
            ?assertMatch([{?HEADERS, _, Sid, _}], Frames),
            [{?HEADERS, Flags, Sid, _}] = Frames,
            ?assert(has(Flags, ?END_STREAM)),
            ?assert(has(Flags, ?END_HEADERS)),
            ?assertEqual(all_ok, result(Sid)),
            Raw2
        end, Raw0, Cases)
    end).

streamed_body_dropped() ->
    Test = self(),
    Handler = fun(Conn, Sid, Method, _Path, _H) ->
        Status = case Method of <<"HEAD">> -> 200; _ -> 204 end,
        R = [h2:send_response(Conn, Sid, Status, []),
             h2:send_data(Conn, Sid, <<"a">>, false),
             h2:send_data(Conn, Sid, <<"b">>, false),
             h2:send_data(Conn, Sid, <<"c">>, false, #{block => 1000}),
             h2:send_trailers(Conn, Sid, [{<<"x-trailer">>, <<"1">>}])],
        Test ! {result, Sid, R}
    end,
    with_raw_client(#{}, Handler, fun(Raw0) ->
        lists:foldl(fun(Method, Raw) ->
            {Sid, Raw1} = request(Raw, Method, <<"/">>),
            {Frames, Raw2} = stream_frames(Raw1, Sid),
            ?assertMatch([{?HEADERS, _, Sid, _}], Frames),
            ?assertEqual(all_ok, result(Sid)),
            Raw2
        end, Raw0, [<<"GET">>, <<"HEAD">>])
    end).

continuation() ->
    Test = self(),
    Big = binary:copy(<<"v">>, 20000),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        R = [h2:send_response(Conn, Sid, 200, [{<<"x-big">>, Big}]),
             h2:send_data(Conn, Sid, <<"body">>, true)],
        Test ! {result, Sid, R}
    end,
    with_raw_client(#{}, Handler, fun(Raw0) ->
        {Sid, Raw1} = request(Raw0, <<"HEAD">>, <<"/">>),
        {Frames, _} = stream_frames(Raw1, Sid),
        [{?HEADERS, HFlags, Sid, _} | Conts] = Frames,
        ?assert(has(HFlags, ?END_STREAM)),
        ?assertNot(has(HFlags, ?END_HEADERS)),
        ?assert(Conts =/= []),
        ?assert(lists:all(fun({T, _, _, _}) -> T =:= ?CONTINUATION end, Conts)),
        {?CONTINUATION, LastFlags, Sid, _} = lists:last(Conts),
        ?assert(has(LastFlags, ?END_HEADERS)),
        ?assertEqual(all_ok, result(Sid))
    end).

content_length() ->
    Test = self(),
    CL = [{<<"content-length">>, <<"5">>}],
    Handler = fun(Conn, Sid, _M, Path, _H) ->
        R = case Path of
            <<"/103">> ->
                [h2:send_response(Conn, Sid, 103, CL),
                 h2:respond(Conn, Sid, 200, [], <<"hello">>)];
            <<"/100">> ->
                [h2:send_response(Conn, Sid, 100, CL),
                 h2:respond(Conn, Sid, 200, [], <<"hello">>)];
            <<"/", S/binary>> ->
                [h2:send_response(Conn, Sid, binary_to_integer(S), CL)]
        end,
        Test ! {result, Sid, R}
    end,
    with_raw_client(#{}, Handler, fun(Raw0) ->
        Check = fun(Method, Path, Expect, Raw) ->
            {Sid, Raw1} = request(Raw, Method, Path),
            {Frames, Raw2} = stream_frames(Raw1, Sid),
            {Blocks, Raw3} = decode_blocks(Frames, Raw2),
            ?assertEqual(Expect,
                         [{proplists:get_value(<<":status">>, H),
                           proplists:get_value(<<"content-length">>, H)}
                          || H <- Blocks]),
            ?assertEqual(all_ok, result(Sid)),
            Raw3
        end,
        Raw1 = Check(<<"GET">>, <<"/204">>, [{<<"204">>, undefined}], Raw0),
        Raw2 = Check(<<"GET">>, <<"/304">>, [{<<"304">>, <<"5">>}], Raw1),
        Raw3 = Check(<<"HEAD">>, <<"/200">>, [{<<"200">>, <<"5">>}], Raw2),
        Raw4 = Check(<<"GET">>, <<"/103">>,
                     [{<<"103">>, undefined}, {<<"200">>, undefined}], Raw3),
        _ = Check(<<"GET">>, <<"/100">>,
                  [{<<"100">>, undefined}, {<<"200">>, undefined}], Raw4)
    end).

informational() ->
    Test = self(),
    Link = [{<<"link">>, <<"</s.css>; rel=preload">>}],
    Handler = fun(Conn, Sid, Method, _P, _H) ->
        R = case Method of
            <<"HEAD">> ->
                [h2:send_response(Conn, Sid, 103, Link),
                 h2:send_response(Conn, Sid, 200, [])];
            _ ->
                [h2:send_response(Conn, Sid, 100, []),
                 h2:send_response(Conn, Sid, 103, Link),
                 h2:respond(Conn, Sid, 200, [], <<"hi">>)]
        end,
        Test ! {result, Sid, R}
    end,
    with_raw_client(#{}, Handler, fun(Raw0) ->
        {Sid1, Raw1} = request(Raw0, <<"GET">>, <<"/">>),
        {F1, Raw2} = stream_frames(Raw1, Sid1),
        ?assertMatch([{?HEADERS, _, _, _}, {?HEADERS, _, _, _},
                      {?HEADERS, _, _, _}, {?DATA, _, _, <<"hi">>}], F1),
        [{_, A, _, _}, {_, B, _, _}, {_, C, _, _}, {_, D, _, _}] = F1,
        ?assertNot(has(A, ?END_STREAM)),
        ?assertNot(has(B, ?END_STREAM)),
        ?assertNot(has(C, ?END_STREAM)),
        ?assert(has(D, ?END_STREAM)),
        {B1, Raw3} = decode_blocks(F1, Raw2),
        ?assertEqual([<<"100">>, <<"103">>, <<"200">>],
                     [proplists:get_value(<<":status">>, H) || H <- B1]),
        ?assertEqual(all_ok, result(Sid1)),

        %% A 103 on HEAD must not end the stream; the 200 does.
        {Sid2, Raw4} = request(Raw3, <<"HEAD">>, <<"/">>),
        {F2, Raw5} = stream_frames(Raw4, Sid2),
        ?assertMatch([{?HEADERS, _, _, _}, {?HEADERS, _, _, _}], F2),
        [{_, E, _, _}, {_, F, _, _}] = F2,
        ?assertNot(has(E, ?END_STREAM)),
        ?assert(has(F, ?END_STREAM)),
        {B2, _} = decode_blocks(F2, Raw5),
        ?assertEqual([<<"103">>, <<"200">>],
                     [proplists:get_value(<<":status">>, H) || H <- B2]),
        ?assertEqual(all_ok, result(Sid2))
    end).

informational_misuse() ->
    Test = self(),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        R = [h2:respond(Conn, Sid, 103, [], <<>>),
             h2:send_response(Conn, Sid, 103, []),
             h2:send_data(Conn, Sid, <<"x">>, false),
             h2:send_trailers(Conn, Sid, [{<<"x-t">>, <<"1">>}]),
             h2:send_response(Conn, Sid, 204, []),
             h2:send_response(Conn, Sid, 103, [])],
        Test ! {result, Sid, R}
    end,
    with_raw_client(#{}, Handler, fun(Raw0) ->
        {Sid, Raw1} = request(Raw0, <<"GET">>, <<"/">>),
        {Frames, _} = stream_frames(Raw1, Sid),
        ?assertMatch([{?HEADERS, _, _, _}, {?HEADERS, _, _, _}], Frames),
        receive
            {result, Sid, R} ->
                ?assertEqual([{error, informational_status},
                              ok,
                              {error, no_final_response},
                              {error, no_final_response},
                              ok,
                              {error, final_response_sent}], R)
        after 5000 -> ?assert(false)
        end
    end).

%% With one stream allowed at a time, a second request is only accepted if the
%% 204 stream is fully closed. Its body is exactly the initial connection
%% window and arrives with no WINDOW_UPDATE from us, so the 204 charged nothing.
connection_stays_healthy() ->
    Test = self(),
    Window = 65535,
    Handler = fun(Conn, Sid, _M, Path, _H) ->
        R = case Path of
            <<"/204">> ->
                [h2:send_response(Conn, Sid, 204, []),
                 h2:send_data(Conn, Sid, binary:copy(<<"x">>, 1000), true)];
            <<"/full">> ->
                [h2:respond(Conn, Sid, 200, [], binary:copy(<<"y">>, Window))]
        end,
        Test ! {result, Sid, R}
    end,
    Settings = #{settings => #{max_concurrent_streams => 1}},
    with_raw_client(Settings, Handler, fun(Raw0) ->
        {Sid1, Raw1} = request(Raw0, <<"GET">>, <<"/204">>),
        {F1, Raw2} = stream_frames(Raw1, Sid1),
        ?assertMatch([{?HEADERS, _, _, _}], F1),
        ?assertEqual(all_ok, result(Sid1)),
        {Sid2, Raw3} = request(Raw2, <<"GET">>, <<"/full">>),
        {F2, _} = stream_frames(Raw3, Sid2),
        ?assertEqual([], [F || {?RST_STREAM, _, _, _} = F <- F2]),
        Body = iolist_to_binary([P || {?DATA, _, _, P} <- F2]),
        ?assertEqual(Window, byte_size(Body)),
        {?DATA, Last, _, _} = lists:last(F2),
        ?assert(has(Last, ?END_STREAM)),
        ?assertEqual(all_ok, result(Sid2))
    end).

early_204_upload() ->
    Test = self(),
    Handler = fun(Conn, Sid, _M, _P, _H) ->
        Test ! {result, Sid, [h2:send_response(Conn, Sid, 204, [])]}
    end,
    with_raw_client(#{}, Handler, fun(Raw0) ->
        {Sid, Raw1} = request(Raw0, <<"POST">>, <<"/">>, false),
        {F1, Raw2} = stream_frames(Raw1, Sid),
        ?assertMatch([{?HEADERS, _, _, _}], F1),
        ?assertEqual(all_ok, result(Sid)),
        ok = send(Raw2, [h2_frame:encode(h2_frame:data(Sid, <<"abc">>, false)),
                         h2_frame:encode(h2_frame:data(Sid, <<"def">>, true))]),
        {Late, _} = read_frames(Raw2, fun(_) -> false end, 500),
        ?assertEqual([], [F || {T, _, _, _} = F <- Late,
                               T =:= ?RST_STREAM orelse T =:= ?GOAWAY])
    end).

%% The server keeps the last 100 closed stream records. Close more than that
%% between send_response and send_data on one stream.
evicted_record() ->
    Test = self(),
    Handler = fun(Conn, Sid, _M, Path, _H) ->
        case Path of
            <<"/hold">> ->
                ok = h2:send_response(Conn, Sid, 204, []),
                Test ! {holding, self()},
                receive go -> ok end,
                Test ! {result, Sid, [h2:send_data(Conn, Sid, <<"x">>, true),
                                      h2:send_trailers(Conn, Sid, [])]};
            _ ->
                ok = h2:send_response(Conn, Sid, 204, [])
        end
    end,
    with_raw_client(#{}, Handler, fun(Raw0) ->
        {Held, Raw1} = request(Raw0, <<"GET">>, <<"/hold">>),
        Pid = receive {holding, P} -> P after 5000 -> error(no_hold) end,
        {_, Raw2} = stream_frames(Raw1, Held),
        Raw3 = lists:foldl(fun(_, R) ->
            {S, R1} = request(R, <<"GET">>, <<"/other">>),
            {_, R2} = stream_frames(R1, S),
            R2
        end, Raw2, lists:seq(1, 150)),
        Pid ! go,
        ?assertEqual(all_ok, result(Held)),
        {Late, _} = read_frames(Raw3, fun(_) -> false end, 300),
        ?assertEqual([], [F || {_, _, S, _} = F <- Late, S =:= Held])
    end).

%% ---------------------------------------------------------------------------
%% Client receiving
%% ---------------------------------------------------------------------------

client_length_mismatch() ->
    Reply = fun(Sid, Enc) ->
        {Block, _} = h2_hpack:encode([{<<":status">>, <<"200">>},
                                      {<<"content-length">>, <<"10">>}], Enc),
        [h2_frame:encode(h2_frame:headers(Sid, Block, false)),
         h2_frame:encode(h2_frame:data(Sid, <<"hello">>, true))]
    end,
    with_raw_server(Reply, fun(Conn, Peer) ->
        {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"x">>}]),
        ?assertEqual({rst, ?PROTOCOL_ERROR}, peer_saw(Peer)),
        ?assertEqual(protocol_error, stream_reset(Conn, Sid)),
        ?assertEqual([], data_events(Conn, Sid))
    end).

client_data_after_204() ->
    Reply = fun(Sid, Enc) ->
        {Block, _} = h2_hpack:encode([{<<":status">>, <<"204">>}], Enc),
        [h2_frame:encode(h2_frame:headers(Sid, Block, true)),
         h2_frame:encode(h2_frame:data(Sid, <<"oops">>, true))]
    end,
    with_raw_server(Reply, fun(Conn, Peer) ->
        {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"x">>}]),
        %% RFC 9113 §5.1: a frame after END_STREAM is a connection error.
        ?assertEqual({goaway, ?STREAM_CLOSED}, peer_saw(Peer)),
        ?assertEqual([<<>>], data_events(Conn, Sid))
    end).

client_no_end_stream() ->
    lists:foreach(fun({Method, Status}) ->
        Reply = fun(Sid, Enc) ->
            {Block, _} = h2_hpack:encode([{<<":status">>, Status}], Enc),
            [h2_frame:encode(h2_frame:headers(Sid, Block, false))]
        end,
        with_raw_server(Reply, fun(Conn, Peer) ->
            {ok, Sid} = h2:request(Conn, Method, <<"/">>, [{<<"host">>, <<"x">>}]),
            ?assertEqual({rst, ?PROTOCOL_ERROR}, peer_saw(Peer)),
            ?assertEqual(protocol_error, stream_reset(Conn, Sid))
        end)
    end, [{<<"GET">>, <<"304">>}, {<<"HEAD">>, <<"200">>}]).

client_304_complete() ->
    Reply = fun(Sid, Enc) ->
        {Block, _} = h2_hpack:encode([{<<":status">>, <<"304">>},
                                      {<<"content-length">>, <<"42">>}], Enc),
        [h2_frame:encode(h2_frame:headers(Sid, Block, true))]
    end,
    with_raw_server(Reply, fun(Conn, _Peer) ->
        {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"x">>}]),
        receive {h2, Conn, {response, Sid, 304, _}} -> ok
        after 500 -> error(no_response) end,
        receive {h2, Conn, {data, Sid, <<>>, true}} -> ok
        after 500 -> error(not_complete) end
    end).

%% ---------------------------------------------------------------------------
%% Raw client against an h2 server
%% ---------------------------------------------------------------------------

with_raw_client(Opts, Handler, Fun) ->
    {ok, Ref} = h2:start_server(0, Opts#{transport => tcp, handler => Handler}),
    {ok, Sock} = gen_tcp:connect("127.0.0.1", h2:server_port(Ref),
                                 [binary, {active, false}, {packet, raw}], 5000),
    ok = gen_tcp:send(Sock, [?PREFACE,
                             h2_frame:encode(h2_frame:settings([])),
                             h2_frame:encode(h2_frame:settings_ack())]),
    Raw = #{sock => Sock, buf => <<>>, next => 1,
            enc => h2_hpack:new_context(), dec => h2_hpack:new_context()},
    try
        Fun(Raw)
    after
        _ = gen_tcp:close(Sock),
        h2:stop_server(Ref)
    end.

request(Raw, Method, Path) ->
    request(Raw, Method, Path, true).

request(#{next := Sid, enc := Enc} = Raw, Method, Path, EndStream) ->
    Headers = [{<<":method">>, Method}, {<<":path">>, Path},
               {<<":scheme">>, <<"http">>}, {<<":authority">>, <<"x">>}],
    {Block, Enc1} = h2_hpack:encode(Headers, Enc),
    ok = send(Raw, h2_frame:encode(h2_frame:headers(Sid, Block, EndStream))),
    {Sid, Raw#{next := Sid + 2, enc := Enc1}}.

send(#{sock := Sock}, IoData) -> gen_tcp:send(Sock, IoData).

%% Frames on stream Sid until the one carrying END_STREAM (or an RST_STREAM),
%% in order, with a short grace period after it to catch anything that follows.
stream_frames(Raw, Sid) ->
    {Frames, Raw1} = read_frames(Raw, fun({T, F, S, _}) ->
        S =:= Sid andalso
            ((T =:= ?HEADERS orelse T =:= ?DATA) andalso has(F, ?END_STREAM)
             orelse T =:= ?RST_STREAM)
    end, 5000),
    {After, Raw2} = read_frames(Raw1, fun(_) -> false end, 100),
    {[F || {_, _, S, _} = F <- Frames ++ After, S =:= Sid], Raw2}.

%% Read frames until Stop(Frame) is true (that frame included) or Ms elapse.
read_frames(Raw, Stop, Ms) ->
    read_frames(Raw, Stop, erlang:monotonic_time(millisecond) + Ms, []).

read_frames(#{buf := Buf, sock := Sock} = Raw, Stop, Deadline, Acc) ->
    case Buf of
        <<Len:24, Type:8, Flags:8, _:1, Sid:31, Payload:Len/binary, Rest/binary>> ->
            Frame = {Type, Flags, Sid, Payload},
            Raw1 = Raw#{buf := Rest},
            case Stop(Frame) of
                true  -> {lists:reverse([Frame | Acc]), Raw1};
                false -> read_frames(Raw1, Stop, Deadline, [Frame | Acc])
            end;
        _ ->
            T = Deadline - erlang:monotonic_time(millisecond),
            case T > 0 andalso gen_tcp:recv(Sock, 0, T) of
                {ok, Data} ->
                    read_frames(Raw#{buf := <<Buf/binary, Data/binary>>},
                                Stop, Deadline, Acc);
                _ ->
                    {lists:reverse(Acc), Raw}
            end
    end.

%% Decode every header block in Frames (HEADERS + CONTINUATION) in order.
decode_blocks(Frames, Raw) ->
    decode_blocks(Frames, Raw, <<>>, []).

decode_blocks([], Raw, _Pending, Acc) ->
    {lists:reverse(Acc), Raw};
decode_blocks([{T, Flags, _, P} | Rest], #{dec := Dec} = Raw, Pending, Acc)
  when T =:= ?HEADERS; T =:= ?CONTINUATION ->
    Block = <<Pending/binary, P/binary>>,
    case has(Flags, ?END_HEADERS) of
        true ->
            {ok, Headers, Dec1} = h2_hpack:decode(Block, Dec),
            decode_blocks(Rest, Raw#{dec := Dec1}, <<>>, [Headers | Acc]);
        false ->
            decode_blocks(Rest, Raw, Block, Acc)
    end;
decode_blocks([_ | Rest], Raw, Pending, Acc) ->
    decode_blocks(Rest, Raw, Pending, Acc).

has(Flags, Bit) -> Flags band Bit =/= 0.

result(Sid) ->
    receive
        {result, Sid, R} ->
            case lists:all(fun(X) -> X =:= ok end, R) of
                true  -> all_ok;
                false -> R
            end
    after 5000 ->
        no_result
    end.

%% ---------------------------------------------------------------------------
%% Raw server against an h2 client
%% ---------------------------------------------------------------------------

%% Reply(StreamId, EncodeContext) returns the frames the peer answers the
%% first request with. The peer then reports the first RST_STREAM or GOAWAY it
%% reads back to the test.
with_raw_server(Reply, Fun) ->
    {ok, LS} = gen_tcp:listen(0, [binary, {active, false}, {packet, raw},
                                  {reuseaddr, true}]),
    {ok, Port} = inet:port(LS),
    Test = self(),
    Peer = spawn_link(fun() -> raw_server(LS, Reply, Test) end),
    {ok, Conn} = h2:connect("127.0.0.1", Port, #{transport => tcp}),
    ok = h2:wait_connected(Conn),
    try
        Fun(Conn, Peer)
    after
        try h2:close(Conn) catch _:_ -> ok end,
        unlink(Peer),
        exit(Peer, kill),
        gen_tcp:close(LS),
        flush()
    end.

raw_server(LS, Reply, Test) ->
    {ok, S} = gen_tcp:accept(LS, 5000),
    {ok, ?PREFACE} = gen_tcp:recv(S, byte_size(?PREFACE), 5000),
    ok = gen_tcp:send(S, [h2_frame:encode(h2_frame:settings([])),
                          h2_frame:encode(h2_frame:settings_ack())]),
    Raw = #{sock => S, buf => <<>>},
    {Frames, Raw1} = read_frames(Raw, fun({T, _, _, _}) -> T =:= ?HEADERS end, 5000),
    {?HEADERS, _, Sid, _} = lists:last(Frames),
    ok = gen_tcp:send(S, Reply(Sid, h2_hpack:new_context())),
    {Back, _} = read_frames(Raw1, fun({T, _, _, _}) ->
        T =:= ?RST_STREAM orelse T =:= ?GOAWAY
    end, 3000),
    Saw = case lists:last([{rst_or_goaway} | Back]) of
        {?RST_STREAM, _, _, <<Code:32>>} -> {rst, Code};
        {?GOAWAY, _, _, <<_:32, Code:32, _/binary>>} -> {goaway, Code};
        _ -> nothing
    end,
    Test ! {peer_saw, self(), Saw},
    receive stop -> ok after 5000 -> ok end,
    gen_tcp:close(S).

peer_saw(Peer) ->
    receive {peer_saw, Peer, Saw} -> Saw after 5000 -> no_report end.

stream_reset(Conn, Sid) ->
    receive {h2, Conn, {stream_reset, Sid, Reason}} -> Reason
    after 2000 -> no_reset
    end.

data_events(Conn, Sid) ->
    receive {h2, Conn, {data, Sid, D, _}} -> [D | data_events(Conn, Sid)]
    after 200 -> []
    end.

flush() ->
    receive _ -> flush() after 0 -> ok end.

-endif.
