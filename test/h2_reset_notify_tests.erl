%% @doc A stream that h2 resets because of what the peer sent is reported to
%% its handler (or the owner) as `{stream_reset, StreamId, ErrorCode}', once,
%% and is closed (RFC 9113 §5.1, §5.4.2).
%%
%% The case that started this: on a CONNECT tunnel, HEADERS after the 2xx are
%% trailers, which a tunnel does not carry (RFC 9113 §8.5). The stream was
%% reset on the wire and the handler was never told.
%%
%% Every case drives a raw peer over gen_tcp and asserts the exact frames.
-module(h2_reset_notify_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).

-define(HEADERS, 1).
-define(RST_STREAM, 3).
-define(GOAWAY, 7).
-define(WINDOW_UPDATE, 8).

-define(END_STREAM, 16#1).

-define(PROTOCOL_ERROR, 1).
-define(FLOW_CONTROL_ERROR, 3).
-define(STREAM_CLOSED, 5).
-define(ENHANCE_YOUR_CALM, 11).

reset_notify_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"server: trailers on a CONNECT tunnel reset the stream and tell the handler",
       {timeout, 30, fun server_tunnel_trailers/0}},
      {"client: trailers on a CONNECT tunnel reset the stream and tell the handler",
       {timeout, 30, fun client_tunnel_trailers/0}},
      {"server: trailers before the 2xx, and on an ordinary request, are delivered",
       {timeout, 30, fun trailers_still_delivered/0}},
      {"server: a stream window overflow tells the handler",
       {timeout, 30, fun window_overflow/0}},
      {"server: a zero WINDOW_UPDATE tells the handler",
       {timeout, 30, fun zero_window_update/0}},
      {"server: trailers without END_STREAM tell the handler and close the stream",
       {timeout, 30, fun trailers_without_end_stream/0}},
      {"server: HEADERS after the request ended tell the handler and close the stream",
       {timeout, 30, fun headers_after_end_stream/0}},
      {"server: DATA after the request ended tells the handler and closes the stream",
       {timeout, 30, fun data_after_end_stream/0}},
      {"client: a reset is reported once to the owner",
       {timeout, 30, fun client_reported_once/0}},
      {"client: a malformed response is reported to the owner",
       {timeout, 30, fun client_malformed_response/0}},
      {"server: resets caused by the peer stay under the per-second budget",
       {timeout, 30, fun reset_budget/0}}]}.

%% ---------------------------------------------------------------------------
%% CONNECT tunnel
%% ---------------------------------------------------------------------------

server_tunnel_trailers() ->
    with_raw_client(fun(Raw0) ->
        {Sid, Raw1} = connect(Raw0, <<"/respond">>),
        Conn = ready(Sid),
        {_, Raw2} = read_frames(Raw1, fun({T, _, S, _}) ->
            T =:= ?HEADERS andalso S =:= Sid
        end, 5000),
        {_, Raw3} = trailers(Raw2, Sid, true),
        ?assertEqual({rst, ?PROTOCOL_ERROR}, wire_reset(Raw3, Sid)),
        ?assertEqual([protocol_error], stream_resets(Conn, Sid)),
        ?assertMatch({error, _}, h2:send_data(Conn, Sid, <<"x">>, false))
    end).

client_tunnel_trailers() ->
    Reply = fun(Sid, Enc0) ->
        {Block1, Enc1} = h2_hpack:encode([{<<":status">>, <<"200">>}], Enc0),
        {Block2, _} = h2_hpack:encode([{<<"x-trailer">>, <<"1">>}], Enc1),
        [h2_frame:encode(h2_frame:headers(Sid, Block1, false)),
         h2_frame:encode(h2_frame:headers(Sid, Block2, true))]
    end,
    with_raw_server(Reply, fun(Conn, Peer) ->
        Test = self(),
        Handler = spawn_link(fun() -> relay(Test) end),
        Sid = tunnel_request(Conn, Handler, 50),
        ?assertEqual({rst, ?PROTOCOL_ERROR}, peer_saw(Peer)),
        receive {relayed, {h2, Conn, {response, Sid, 200, _}}} -> ok
        after 2000 -> error(no_response) end,
        receive {relayed, {h2, Conn, {stream_reset, Sid, Reason}}} ->
            ?assertEqual(protocol_error, Reason)
        after 2000 -> error(handler_not_told) end,
        ?assertMatch({error, _}, h2:send_data(Conn, Sid, <<"x">>, false))
    end).

trailers_still_delivered() ->
    with_raw_client(fun(Raw0) ->
        %% CONNECT with no response yet: not a tunnel, trailers pass.
        {Sid1, Raw1} = connect(Raw0, <<"/hold">>),
        Conn = ready(Sid1),
        {_, Raw2} = trailers(Raw1, Sid1, true),
        ?assertMatch([{<<"x-trailer">>, <<"1">>}], trailers_event(Conn, Sid1)),
        %% An ordinary request body ending on trailers.
        {Sid2, Raw3} = post(Raw2, <<"/hold">>, false),
        Conn = ready(Sid2),
        {_, _} = trailers(Raw3, Sid2, true),
        ?assertMatch([{<<"x-trailer">>, <<"1">>}], trailers_event(Conn, Sid2)),
        ?assertEqual([], stream_resets(Conn, Sid1)),
        ?assertEqual([], stream_resets(Conn, Sid2))
    end).

%% ---------------------------------------------------------------------------
%% Other resets caused by the peer
%% ---------------------------------------------------------------------------

window_overflow() ->
    with_raw_client(fun(Raw0) ->
        {Sid, Raw1} = post(Raw0, <<"/hold">>, false),
        Conn = ready(Sid),
        %% RFC 9113 §6.9.1: a window above 2^31-1 is a stream error.
        ok = send(Raw1, <<4:24, ?WINDOW_UPDATE, 0, 0:1, Sid:31, 0:1, 16#7fffffff:31>>),
        ?assertEqual({rst, ?FLOW_CONTROL_ERROR}, wire_reset(Raw1, Sid)),
        ?assertEqual([flow_control_error], stream_resets(Conn, Sid))
    end).

zero_window_update() ->
    with_raw_client(fun(Raw0) ->
        {Sid, Raw1} = post(Raw0, <<"/hold">>, false),
        Conn = ready(Sid),
        %% RFC 9113 §6.9: a zero increment is a stream error PROTOCOL_ERROR.
        ok = send(Raw1, <<4:24, ?WINDOW_UPDATE, 0, 0:1, Sid:31, 0:32>>),
        ?assertEqual({rst, ?PROTOCOL_ERROR}, wire_reset(Raw1, Sid)),
        ?assertEqual([protocol_error], stream_resets(Conn, Sid))
    end).

trailers_without_end_stream() ->
    with_raw_client(fun(Raw0) ->
        {Sid, Raw1} = post(Raw0, <<"/hold">>, false),
        Conn = ready(Sid),
        %% RFC 9113 §8.1: trailers end the stream.
        {_, Raw2} = trailers(Raw1, Sid, false),
        ?assertEqual({rst, ?PROTOCOL_ERROR}, wire_reset(Raw2, Sid)),
        ?assertEqual([protocol_error], stream_resets(Conn, Sid)),
        ?assertMatch({error, _}, h2:send_response(Conn, Sid, 200, []))
    end).

headers_after_end_stream() ->
    with_raw_client(fun(Raw0) ->
        {Sid, Raw1} = post(Raw0, <<"/hold">>, true),
        Conn = ready(Sid),
        %% RFC 9113 §5.1: HEADERS on a half-closed (remote) stream.
        {_, Raw2} = trailers(Raw1, Sid, true),
        ?assertEqual({rst, ?STREAM_CLOSED}, wire_reset(Raw2, Sid)),
        ?assertEqual([stream_closed], stream_resets(Conn, Sid)),
        ?assertMatch({error, _}, h2:send_response(Conn, Sid, 200, []))
    end).

data_after_end_stream() ->
    with_raw_client(fun(Raw0) ->
        {Sid, Raw1} = post(Raw0, <<"/hold">>, true),
        Conn = ready(Sid),
        %% RFC 9113 §5.1: DATA on a half-closed (remote) stream.
        ok = send(Raw1, h2_frame:encode(h2_frame:data(Sid, <<"late">>, false))),
        ?assertEqual({rst, ?STREAM_CLOSED}, wire_reset(Raw1, Sid)),
        ?assertEqual([stream_closed], stream_resets(Conn, Sid)),
        ?assertMatch({error, _}, h2:send_response(Conn, Sid, 200, []))
    end).

client_reported_once() ->
    %% Content-Length mismatch, then HEAD answered without END_STREAM.
    Mismatch = fun(Sid, Enc) ->
        {Block, _} = h2_hpack:encode([{<<":status">>, <<"200">>},
                                      {<<"content-length">>, <<"10">>}], Enc),
        [h2_frame:encode(h2_frame:headers(Sid, Block, false)),
         h2_frame:encode(h2_frame:data(Sid, <<"hello">>, true))]
    end,
    Head = fun(Sid, Enc) ->
        {Block, _} = h2_hpack:encode([{<<":status">>, <<"200">>}], Enc),
        [h2_frame:encode(h2_frame:headers(Sid, Block, false))]
    end,
    lists:foreach(fun({Method, Reply}) ->
        with_raw_server(Reply, fun(Conn, Peer) ->
            {ok, Sid} = h2:request(Conn, Method, <<"/">>, [{<<"host">>, <<"x">>}]),
            ?assertEqual({rst, ?PROTOCOL_ERROR}, peer_saw(Peer)),
            ?assertEqual([protocol_error], stream_resets(Conn, Sid))
        end)
    end, [{<<"GET">>, Mismatch}, {<<"HEAD">>, Head}]).

client_malformed_response() ->
    %% RFC 9113 §8.1.1: an unparsable Content-Length makes the response
    %% malformed. The request must not be left waiting.
    Reply = fun(Sid, Enc) ->
        {Block, _} = h2_hpack:encode([{<<":status">>, <<"200">>},
                                      {<<"content-length">>, <<"abc">>}], Enc),
        [h2_frame:encode(h2_frame:headers(Sid, Block, false))]
    end,
    with_raw_server(Reply, fun(Conn, Peer) ->
        {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"x">>}]),
        ?assertEqual({rst, ?PROTOCOL_ERROR}, peer_saw(Peer)),
        ?assertEqual([protocol_error], stream_resets(Conn, Sid)),
        ?assertMatch({error, _}, h2:send_data(Conn, Sid, <<"x">>, false))
    end).

%% CVE-2025-8671 (MadeYouReset): telling the handler does not lift the cap on
%% resets a peer can cause. More than the budget in one burst ends the
%% connection.
reset_budget() ->
    with_raw_client(fun(Raw0) ->
        {Frames, Raw1} = lists:foldl(fun(_, {Acc, #{next := Sid, enc := Enc} = R}) ->
            {B1, Enc1} = h2_hpack:encode(request_headers(<<"POST">>, <<"/quiet">>), Enc),
            {B2, Enc2} = h2_hpack:encode([{<<"x-trailer">>, <<"1">>}], Enc1),
            {[Acc, h2_frame:encode(h2_frame:headers(Sid, B1, false)),
              h2_frame:encode(h2_frame:headers(Sid, B2, false))],
             R#{next := Sid + 2, enc := Enc2}}
        end, {[], Raw0}, lists:seq(1, 300)),
        ok = send(Raw1, Frames),
        {Back, _} = read_frames(Raw1, fun({T, _, _, _}) -> T =:= ?GOAWAY end, 10000),
        ?assertMatch({?GOAWAY, _, 0, <<_:32, ?ENHANCE_YOUR_CALM:32, _/binary>>},
                     lists:last([none | Back]))
    end).

%% ---------------------------------------------------------------------------
%% Raw client against an h2 server
%% ---------------------------------------------------------------------------

%% The server handler registers the test process as the stream handler, then:
%%   /respond  answers 200 (a CONNECT stream becomes a tunnel)
%%   /hold     answers nothing
%%   /quiet    does nothing at all
with_raw_client(Fun) ->
    Test = self(),
    Handler = fun(Conn, Sid, _Method, Path, _Headers) ->
        case Path of
            <<"/quiet">> ->
                ok;
            _ ->
                ok = h2:set_stream_handler(Conn, Sid, Test),
                Path =:= <<"/respond">> andalso
                    (ok = h2:send_response(Conn, Sid, 200, [])),
                Test ! {ready, Sid, Conn}
        end
    end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler,
                                     enable_connect_protocol => true}),
    {ok, Sock} = gen_tcp:connect("127.0.0.1", h2:server_port(Ref),
                                 [binary, {active, false}, {packet, raw}], 5000),
    ok = gen_tcp:send(Sock, [?PREFACE,
                             h2_frame:encode(h2_frame:settings([])),
                             h2_frame:encode(h2_frame:settings_ack())]),
    Raw = #{sock => Sock, buf => <<>>, next => 1, enc => h2_hpack:new_context()},
    try
        Fun(Raw)
    after
        _ = gen_tcp:close(Sock),
        h2:stop_server(Ref),
        flush()
    end.

request_headers(Method, Path) ->
    [{<<":method">>, Method}, {<<":scheme">>, <<"http">>},
     {<<":path">>, Path}, {<<":authority">>, <<"x">>}].

%% Extended CONNECT (RFC 8441), stream left open.
connect(Raw, Path) ->
    open(Raw, [{<<":method">>, <<"CONNECT">>}, {<<":protocol">>, <<"connect-tcp">>},
               {<<":scheme">>, <<"http">>}, {<<":path">>, Path},
               {<<":authority">>, <<"x">>}], false).

post(Raw, Path, EndStream) ->
    open(Raw, request_headers(<<"POST">>, Path), EndStream).

open(#{next := Sid} = Raw, Headers, EndStream) ->
    {ok, Raw1} = headers(Raw, Sid, Headers, EndStream),
    {Sid, Raw1#{next := Sid + 2}}.

trailers(Raw, Sid, EndStream) ->
    headers(Raw, Sid, [{<<"x-trailer">>, <<"1">>}], EndStream).

headers(#{enc := Enc} = Raw, Sid, Headers, EndStream) ->
    {Block, Enc1} = h2_hpack:encode(Headers, Enc),
    ok = send(Raw, h2_frame:encode(h2_frame:headers(Sid, Block, EndStream))),
    {ok, Raw#{enc := Enc1}}.

send(#{sock := Sock}, IoData) -> gen_tcp:send(Sock, IoData).

%% The server handler ran for Sid; returns the server connection.
ready(Sid) ->
    receive {ready, Sid, Conn} -> Conn
    after 5000 -> error({handler_not_run, Sid})
    end.

%% The RST_STREAM the server sent on Sid.
wire_reset(Raw, Sid) ->
    {Frames, _} = read_frames(Raw, fun({T, _, S, _}) ->
        T =:= ?RST_STREAM andalso S =:= Sid
    end, 5000),
    case lists:last([none | Frames]) of
        {?RST_STREAM, _, Sid, <<Code:32>>} -> {rst, Code};
        _ -> no_reset
    end.

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

%% ---------------------------------------------------------------------------
%% Raw server against an h2 client
%% ---------------------------------------------------------------------------

%% The peer allows Extended CONNECT, answers the first request with
%% Reply(StreamId, EncodeContext), then reports the first RST_STREAM or GOAWAY
%% it reads back to the test.
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
    ok = gen_tcp:send(S, [h2_frame:encode(
                            h2_frame:settings([{enable_connect_protocol, 1}])),
                          h2_frame:encode(h2_frame:settings_ack())]),
    Raw = #{sock => S, buf => <<>>},
    {Frames, Raw1} = read_frames(Raw, fun({T, _, _, _}) -> T =:= ?HEADERS end, 5000),
    {?HEADERS, _, Sid, _} = lists:last(Frames),
    ok = gen_tcp:send(S, Reply(Sid, h2_hpack:new_context())),
    {Back, _} = read_frames(Raw1, fun({T, _, _, _}) ->
        T =:= ?RST_STREAM orelse T =:= ?GOAWAY
    end, 3000),
    Saw = case lists:last([none | Back]) of
        {?RST_STREAM, _, _, <<Code:32>>} -> {rst, Code};
        {?GOAWAY, _, _, <<_:32, Code:32, _/binary>>} -> {goaway, Code};
        _ -> nothing
    end,
    Test ! {peer_saw, self(), Saw},
    receive stop -> ok after 5000 -> ok end,
    gen_tcp:close(S).

peer_saw(Peer) ->
    receive {peer_saw, Peer, Saw} -> Saw after 5000 -> no_report end.

%% Extended CONNECT from the client with Handler as the stream handler. The
%% peer's SETTINGS may not be applied yet, so retry while it is refused.
tunnel_request(Conn, Handler, Tries) ->
    Headers = [{<<":method">>, <<"CONNECT">>}, {<<":scheme">>, <<"http">>},
               {<<":path">>, <<"/">>}, {<<":authority">>, <<"x">>}],
    case h2:request(Conn, Headers, #{protocol => <<"connect-tcp">>,
                                     handler => Handler}) of
        {ok, Sid} ->
            Sid;
        {error, extended_connect_disabled} when Tries > 0 ->
            timer:sleep(20),
            tunnel_request(Conn, Handler, Tries - 1)
    end.

relay(To) ->
    receive Msg -> To ! {relayed, Msg}, relay(To) end.

%% ---------------------------------------------------------------------------
%% Events
%% ---------------------------------------------------------------------------

%% Every stream_reset reported for Sid, waiting long enough to see a second.
stream_resets(Conn, Sid) ->
    receive {h2, Conn, {stream_reset, Sid, Reason}} ->
        [Reason | stream_resets(Conn, Sid, 200)]
    after 2000 -> []
    end.

stream_resets(Conn, Sid, Ms) ->
    receive {h2, Conn, {stream_reset, Sid, Reason}} ->
        [Reason | stream_resets(Conn, Sid, Ms)]
    after Ms -> []
    end.

trailers_event(Conn, Sid) ->
    receive {h2, Conn, {trailers, Sid, Headers}} -> Headers
    after 2000 -> no_trailers
    end.

flush() ->
    receive _ -> flush() after 0 -> ok end.

-endif.
