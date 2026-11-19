%% @doc What the calls that send a header block answer and write:
%% `h2:request/3,4', `h2:send_response/4' and `h2:respond/5'.
%%
%% Each call checks several things before it writes. These tests pin which
%% error is returned, which one wins when two apply, that a refused call
%% writes nothing and leaves the HPACK encoder as it was, and the state the
%% stream is left in. Every case drives a raw peer over gen_tcp.
-module(h2_send_paths_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).

-define(DATA, 0).
-define(HEADERS, 1).
-define(RST_STREAM, 3).
-define(SETTINGS, 4).
-define(WINDOW_UPDATE, 8).

-define(END_STREAM, 16#1).

send_paths_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"request/4: errors, their order, nothing written when refused",
       {timeout, 30, fun request_errors/0}},
      {"request/3: Extended CONNECT guards come before header validation",
       {timeout, 30, fun request_headers_errors/0}},
      {"request: a full connection is reported before anything else",
       {timeout, 30, fun request_full_connection/0}},
      {"request and response calls on the wrong side",
       {timeout, 30, fun wrong_side/0}},
      {"send_response: errors and their order",
       {timeout, 30, fun send_response_errors/0}},
      {"send_response: a tunnel response refuses a body length first",
       {timeout, 30, fun tunnel_response_errors/0}},
      {"respond/5: errors and their order",
       {timeout, 30, fun respond_errors/0}},
      {"refused responses write nothing and keep the HPACK encoder in step",
       {timeout, 30, fun refused_writes_nothing/0}},
      {"stream state after a response with and without END_STREAM",
       {timeout, 30, fun stream_state_after_response/0}},
      {"respond/5 with a body over the peer's window still delivers it all",
       {timeout, 30, fun respond_over_window/0}}]}.

%% ---------------------------------------------------------------------------
%% Client: request/4 and request/3
%% ---------------------------------------------------------------------------

request_errors() ->
    with_raw_server([{max_header_list_size, 200}], fun(Conn, Peer) ->
        Host = [{<<"host">>, <<"x">>}],
        Big = {<<"x-big">>, binary:copy(<<"a">>, 300)},
        Bad = {<<"Bad Name">>, <<"v">>},
        %% CONNECT needs an authority.
        ?assertEqual({error, missing_authority},
                     h2:request(Conn, <<"CONNECT">>, <<"/">>, [])),
        %% That check comes before header validation.
        ?assertEqual({error, missing_authority},
                     h2:request(Conn, <<"CONNECT">>, <<"/">>, [Bad])),
        ?assertEqual({error, protocol_error},
                     h2:request(Conn, <<"GET">>, <<"/">>, [Bad | Host])),
        ?assertEqual({error, header_list_too_large},
                     h2:request(Conn, <<"GET">>, <<"/">>, [Big | Host])),
        %% Validation comes before the size limit.
        ?assertEqual({error, protocol_error},
                     h2:request(Conn, <<"GET">>, <<"/">>, [Bad, Big | Host])),
        %% Nothing was written, and stream ids were not consumed.
        ?assertEqual({ok, 1}, h2:request(Conn, <<"GET">>, <<"/a">>, Host)),
        ?assertEqual({error, protocol_error},
                     h2:request(Conn, <<"GET">>, <<"/">>, [Bad | Host])),
        ?assertEqual({ok, 3}, h2:request(Conn, <<"GET">>, <<"/b">>, Host)),
        ?assertEqual([{1, <<"/a">>}, {3, <<"/b">>}], request_paths(Peer))
    end).

request_headers_errors() ->
    %% The peer has not enabled Extended CONNECT.
    with_raw_server([], fun(Conn, Peer) ->
        Base = [{<<":scheme">>, <<"http">>}, {<<":path">>, <<"/">>},
                {<<":authority">>, <<"x">>}],
        Proto = {<<":protocol">>, <<"websocket">>},
        Get = {<<":method">>, <<"GET">>},
        Connect = {<<":method">>, <<"CONNECT">>},
        %% RFC 8441: `:protocol' needs CONNECT, and the method is checked
        %% before the peer's setting.
        ?assertEqual({error, extended_connect_method},
                     h2:request(Conn, [Get, Proto | Base], #{})),
        ?assertEqual({error, extended_connect_disabled},
                     h2:request(Conn, [Connect, Proto | Base], #{})),
        %% Both come before header validation.
        ?assertEqual({error, extended_connect_disabled},
                     h2:request(Conn, [Connect, Proto | Base]
                                      ++ [{<<"Bad Name">>, <<"v">>}], #{})),
        ?assertEqual({error, protocol_error},
                     h2:request(Conn, [Get | Base] ++ [{<<"Bad Name">>, <<"v">>}], #{})),
        ?assertEqual({ok, 1}, h2:request(Conn, [Get | Base], #{})),
        ?assertEqual([{1, <<"/">>}], request_paths(Peer))
    end).

request_full_connection() ->
    with_raw_server([{max_concurrent_streams, 1}], fun(Conn, Peer) ->
        Host = [{<<"host">>, <<"x">>}],
        ?assertEqual({ok, 1}, h2:request(Conn, <<"GET">>, <<"/a">>, Host)),
        %% RFC 9113 §5.1.2. Reported before any other problem with the call.
        ?assertEqual({error, max_streams_exceeded},
                     h2:request(Conn, <<"GET">>, <<"/b">>, Host)),
        ?assertEqual({error, max_streams_exceeded},
                     h2:request(Conn, <<"CONNECT">>, <<"/">>, [])),
        ?assertEqual({error, max_streams_exceeded},
                     h2:request(Conn, <<"GET">>, <<"/">>, [{<<"Bad Name">>, <<"v">>}])),
        ?assertEqual({error, max_streams_exceeded},
                     h2:request(Conn, [{<<":method">>, <<"GET">>},
                                       {<<":protocol">>, <<"websocket">>}], #{})),
        ?assertEqual([{1, <<"/a">>}], request_paths(Peer))
    end).

wrong_side() ->
    with_raw_server([], fun(Client, _Peer) ->
        ?assertEqual({error, not_server}, h2:send_response(Client, 1, 200, [])),
        ?assertEqual({error, not_server}, h2:respond(Client, 1, 200, [], <<"x">>))
    end),
    with_raw_client([], fun(Raw0) ->
        {Sid, _Raw1} = get(Raw0, <<"/">>, true),
        Server = ready(Sid),
        ?assertEqual({error, not_client},
                     h2:request(Server, <<"GET">>, <<"/">>, [{<<"host">>, <<"x">>}])),
        ?assertEqual({error, not_client},
                     h2:request(Server, [{<<":method">>, <<"GET">>}], #{}))
    end).

%% ---------------------------------------------------------------------------
%% Server: send_response/4 and respond/5
%% ---------------------------------------------------------------------------

send_response_errors() ->
    with_raw_client([{max_header_list_size, 200}], fun(Raw0) ->
        {Sid, Raw1} = get(Raw0, <<"/">>, false),
        Conn = ready(Sid),
        Big = {<<"x-big">>, binary:copy(<<"a">>, 300)},
        Bad = {<<"Bad Name">>, <<"v">>},
        %% RFC 9113 §8.6: never 101. Checked before the stream is looked up.
        ?assertEqual({error, status_101_forbidden}, h2:send_response(Conn, Sid, 101, [])),
        ?assertEqual({error, status_101_forbidden}, h2:send_response(Conn, 999, 101, [])),
        ?assertEqual({error, unknown_stream}, h2:send_response(Conn, 999, 200, [])),
        ?assertEqual({error, protocol_error}, h2:send_response(Conn, Sid, 200, [Bad])),
        ?assertEqual({error, header_list_too_large}, h2:send_response(Conn, Sid, 200, [Big])),
        ?assertEqual({error, protocol_error}, h2:send_response(Conn, Sid, 200, [Bad, Big])),
        %% An interim response is fine, then the final one.
        ?assertEqual(ok, h2:send_response(Conn, Sid, 103, [])),
        ?assertEqual(ok, h2:send_response(Conn, Sid, 200, [])),
        %% RFC 9110 §15.2: no interim response after the final one, and that
        %% is checked before the headers.
        ?assertEqual({error, final_response_sent}, h2:send_response(Conn, Sid, 103, [])),
        ?assertEqual({error, final_response_sent}, h2:send_response(Conn, Sid, 103, [Bad])),
        %% Once our side has ended, a second final response is a state error.
        ?assertEqual(ok, h2:send_data(Conn, Sid, <<"done">>, true)),
        ?assertEqual({error, invalid_stream_state}, h2:send_response(Conn, Sid, 200, [])),
        ?assertEqual({error, invalid_stream_state}, h2:send_response(Conn, Sid, 200, [Bad])),
        %% On the wire: 103, 200, DATA, and nothing for the refused calls.
        {Frames, _} = stream_frames(Raw1, Sid),
        ?assertMatch([{?HEADERS, _, Sid, _}, {?HEADERS, _, Sid, _},
                      {?DATA, _, Sid, <<"done">>}], Frames)
    end).

tunnel_response_errors() ->
    with_raw_client([], fun(Raw0) ->
        {Sid, Raw1} = connect(Raw0),
        Conn = ready(Sid),
        Length = {<<"content-length">>, <<"0">>},
        Bad = {<<"Bad Name">>, <<"v">>},
        %% RFC 9113 §8.5: a 2xx to CONNECT carries no content-length. Checked
        %% before the headers are validated.
        ?assertEqual({error, banned_header_in_tunnel_response},
                     h2:send_response(Conn, Sid, 200, [Length])),
        ?assertEqual({error, banned_header_in_tunnel_response},
                     h2:send_response(Conn, Sid, 200, [Length, Bad])),
        ?assertEqual({error, banned_header_in_tunnel_response},
                     h2:send_response(Conn, Sid, 204,
                                      [{<<"transfer-encoding">>, <<"chunked">>}])),
        %% Only a 2xx opens a tunnel: other statuses take the normal path.
        ?assertEqual({error, protocol_error}, h2:send_response(Conn, Sid, 404, [Bad])),
        ?assertEqual(ok, h2:send_response(Conn, Sid, 200, [])),
        {Frames, _} = read_frames(Raw1, fun({T, _, S, _}) ->
            T =:= ?HEADERS andalso S =:= Sid
        end, 2000),
        ?assertMatch([{?HEADERS, _, Sid, _}], on_stream(Sid, Frames))
    end).

respond_errors() ->
    with_raw_client([{max_header_list_size, 200}], fun(Raw0) ->
        {Sid, Raw1} = get(Raw0, <<"/">>, true),
        Conn = ready(Sid),
        Big = {<<"x-big">>, binary:copy(<<"a">>, 300)},
        Bad = {<<"Bad Name">>, <<"v">>},
        %% respond/5 sends a complete response; a 1xx is not one. Checked
        %% before the stream is looked up.
        ?assertEqual({error, informational_status}, h2:respond(Conn, Sid, 103, [], <<>>)),
        ?assertEqual({error, informational_status}, h2:respond(Conn, 999, 103, [], <<>>)),
        ?assertEqual({error, status_101_forbidden}, h2:respond(Conn, Sid, 101, [], <<>>)),
        ?assertEqual({error, unknown_stream}, h2:respond(Conn, 999, 200, [], <<"x">>)),
        ?assertEqual({error, protocol_error}, h2:respond(Conn, Sid, 200, [Bad], <<"x">>)),
        ?assertEqual({error, header_list_too_large}, h2:respond(Conn, Sid, 200, [Big], <<"x">>)),
        ?assertEqual({error, protocol_error}, h2:respond(Conn, Sid, 200, [Bad, Big], <<"x">>)),
        ?assertEqual(ok, h2:respond(Conn, Sid, 200, [], <<"body">>)),
        %% The stream has ended on both sides.
        ?assertEqual({error, invalid_stream_state}, h2:respond(Conn, Sid, 200, [], <<"again">>)),
        {Frames, _} = stream_frames(Raw1, Sid),
        ?assertMatch([{?HEADERS, _, Sid, _}, {?DATA, _, Sid, <<"body">>}], Frames)
    end).

refused_writes_nothing() ->
    with_raw_client([], fun(Raw0) ->
        Bad = {<<"Bad Name">>, <<"v">>},
        Tag = {<<"x-tag">>, <<"a value that goes into the dynamic table">>},
        {S1, Raw1} = get(Raw0, <<"/1">>, true),
        Conn = ready(S1),
        {S3, Raw2} = get(Raw1, <<"/3">>, true),
        Conn = ready(S3),
        %% Refused calls carrying the header that a later response reuses: if
        %% a refusal had touched the encoder, the peer's table would be behind.
        ?assertEqual({error, protocol_error}, h2:send_response(Conn, S1, 200, [Tag, Bad])),
        ?assertEqual({error, protocol_error}, h2:respond(Conn, S1, 200, [Tag, Bad], <<"x">>)),
        ?assertEqual(ok, h2:respond(Conn, S1, 200, [Tag], <<"one">>)),
        ?assertEqual({error, protocol_error}, h2:respond(Conn, S3, 200, [Tag, Bad], <<"x">>)),
        ?assertEqual(ok, h2:send_response(Conn, S3, 200, [Tag])),
        ?assertEqual(ok, h2:send_data(Conn, S3, <<"three">>, true)),
        {F1, Raw3} = stream_frames(Raw2, S1),
        {F3, Raw4} = stream_frames(Raw3, S3),
        ?assertMatch([{?HEADERS, _, S1, _}, {?DATA, _, S1, <<"one">>}], F1),
        ?assertMatch([{?HEADERS, _, S3, _}, {?DATA, _, S3, <<"three">>}], F3),
        %% Both blocks decode, in order, with one context.
        {[H1, H3], _} = decode_blocks(F1 ++ F3, Raw4),
        Expect = [{<<":status">>, <<"200">>}, Tag],
        ?assertEqual(Expect, H1),
        ?assertEqual(Expect, H3)
    end).

stream_state_after_response() ->
    with_raw_client([], fun(Raw0) ->
        %% Request already ended, response with no content: closed at once.
        {S1, Raw1} = get(Raw0, <<"/1">>, true),
        Conn = ready(S1),
        ?assertEqual(ok, h2:send_response(Conn, S1, 204, [])),
        {F1, Raw2} = stream_frames(Raw1, S1),
        ?assertMatch([{?HEADERS, Fl, S1, _}] when Fl band ?END_STREAM =/= 0, F1),
        ?assertEqual({error, invalid_stream_state}, h2:send_response(Conn, S1, 200, [])),
        %% Request still open, response with a body: our side ends, the
        %% peer's does not, and its DATA is still accepted.
        {S3, Raw3} = get(Raw2, <<"/3">>, false),
        Conn = ready(S3),
        ?assertEqual(ok, h2:send_response(Conn, S3, 200, [])),
        ?assertEqual(ok, h2:send_data(Conn, S3, <<"body">>, true)),
        {F3, Raw4} = stream_frames(Raw3, S3),
        ?assertMatch([{?HEADERS, Fl, S3, _}, {?DATA, _, S3, <<"body">>}]
                       when Fl band ?END_STREAM =:= 0, F3),
        ok = send(Raw4, h2_frame:encode(h2_frame:data(S3, <<"late">>, true))),
        {After, _} = read_frames(Raw4, fun(_) -> false end, 300),
        ?assertEqual([], [F || {?RST_STREAM, _, _, _} = F <- After])
    end).

respond_over_window() ->
    with_raw_client([], fun(Raw0) ->
        {Sid, Raw1} = get(Raw0, <<"/">>, true),
        Conn = ready(Sid),
        %% 100,000 bytes against the default 65,535-byte windows.
        Body = binary:copy(<<"0123456789">>, 10000),
        ?assertEqual(ok, h2:respond(Conn, Sid, 200, [], Body)),
        {First, Raw2} = read_frames(Raw1, fun(_) -> false end, 500),
        Got1 = data_bytes(Sid, First),
        ?assertEqual(65535, byte_size(Got1)),
        ok = send(Raw2, [<<4:24, ?WINDOW_UPDATE, 0, 0:32, 100000:32>>,
                         <<4:24, ?WINDOW_UPDATE, 0, 0:1, Sid:31, 100000:32>>]),
        {Rest, _} = read_frames(Raw2, fun({T, F, S, _}) ->
            T =:= ?DATA andalso S =:= Sid andalso F band ?END_STREAM =/= 0
        end, 5000),
        ?assertEqual(Body, <<Got1/binary, (data_bytes(Sid, Rest))/binary>>)
    end).

%% ---------------------------------------------------------------------------
%% Raw client against an h2 server
%% ---------------------------------------------------------------------------

%% The server handler only reports the request; the test makes the calls.
with_raw_client(Settings, Fun) ->
    Test = self(),
    Handler = fun(Conn, Sid, _Method, _Path, _Headers) ->
        Test ! {ready, Sid, Conn}
    end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler,
                                     enable_connect_protocol => true}),
    {ok, Sock} = gen_tcp:connect("127.0.0.1", h2:server_port(Ref),
                                 [binary, {active, false}, {packet, raw}], 5000),
    ok = gen_tcp:send(Sock, [?PREFACE,
                             h2_frame:encode(h2_frame:settings(Settings)),
                             h2_frame:encode(h2_frame:settings_ack())]),
    Raw = #{sock => Sock, buf => <<>>, next => 1,
            enc => h2_hpack:new_context(), dec => h2_hpack:new_context()},
    try
        Fun(Raw)
    after
        _ = gen_tcp:close(Sock),
        h2:stop_server(Ref),
        flush()
    end.

get(Raw, Path, EndStream) ->
    open(Raw, [{<<":method">>, <<"POST">>}, {<<":scheme">>, <<"http">>},
               {<<":path">>, Path}, {<<":authority">>, <<"x">>}], EndStream).

connect(Raw) ->
    open(Raw, [{<<":method">>, <<"CONNECT">>}, {<<":protocol">>, <<"connect-tcp">>},
               {<<":scheme">>, <<"http">>}, {<<":path">>, <<"/">>},
               {<<":authority">>, <<"x">>}], false).

open(#{next := Sid, enc := Enc} = Raw, Headers, EndStream) ->
    {Block, Enc1} = h2_hpack:encode(Headers, Enc),
    ok = send(Raw, h2_frame:encode(h2_frame:headers(Sid, Block, EndStream))),
    {Sid, Raw#{next := Sid + 2, enc := Enc1}}.

send(#{sock := Sock}, IoData) -> gen_tcp:send(Sock, IoData).

ready(Sid) ->
    receive {ready, Sid, Conn} -> Conn
    after 5000 -> error({handler_not_run, Sid})
    end.

%% HEADERS and DATA frames on Sid up to the one carrying END_STREAM, plus a
%% short wait to catch anything written after it.
stream_frames(Raw, Sid) ->
    {Frames, Raw1} = read_frames(Raw, fun({T, F, S, _}) ->
        S =:= Sid andalso (T =:= ?HEADERS orelse T =:= ?DATA)
            andalso F band ?END_STREAM =/= 0
    end, 5000),
    {After, Raw2} = read_frames(Raw1, fun(_) -> false end, 100),
    {on_stream(Sid, Frames ++ After), Raw2#{held => held(Sid, Frames ++ After, Raw2)}}.

%% Frames for other streams read while waiting for Sid are kept for the next
%% stream_frames/2 call.
held(Sid, Frames, Raw) ->
    maps:get(held, Raw, []) ++ [F || {T, _, S, _} = F <- Frames, S =/= Sid, S =/= 0,
                                     T =:= ?HEADERS orelse T =:= ?DATA].

on_stream(Sid, Frames) ->
    [F || {T, _, S, _} = F <- Frames, S =:= Sid, T =:= ?HEADERS orelse T =:= ?DATA].

data_bytes(Sid, Frames) ->
    iolist_to_binary([P || {?DATA, _, S, P} <- Frames, S =:= Sid]).

%% Read frames until Stop(Frame) is true (that frame included) or Ms elapse.
%% Frames held back by an earlier stream_frames/2 call are replayed first.
read_frames(Raw, Stop, Ms) ->
    Held = maps:get(held, Raw, []),
    replay(Held, Raw#{held => []}, Stop, erlang:monotonic_time(millisecond) + Ms, []).

replay([], Raw, Stop, Deadline, Acc) ->
    read_frames(Raw, Stop, Deadline, Acc);
replay([Frame | Rest], Raw, Stop, Deadline, Acc) ->
    case Stop(Frame) of
        true  -> {lists:reverse([Frame | Acc]), Raw#{held => Rest}};
        false -> replay(Rest, Raw, Stop, Deadline, [Frame | Acc])
    end.

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

%% Decode every HEADERS block in Frames, in order, with the raw peer's context.
decode_blocks(Frames, #{dec := Dec0} = Raw) ->
    {Blocks, Dec} = lists:foldl(fun({?HEADERS, _, _, Block}, {Acc, D}) ->
                                        {ok, Headers, D1} = h2_hpack:decode(Block, D),
                                        {[Headers | Acc], D1};
                                   (_, AccD) ->
                                        AccD
                                end, {[], Dec0}, Frames),
    {lists:reverse(Blocks), Raw#{dec := Dec}}.

%% ---------------------------------------------------------------------------
%% Raw server against an h2 client
%% ---------------------------------------------------------------------------

%% The peer sends Settings, then only records what the client writes.
with_raw_server(Settings, Fun) ->
    {ok, LS} = gen_tcp:listen(0, [binary, {active, false}, {packet, raw},
                                  {reuseaddr, true}]),
    {ok, Port} = inet:port(LS),
    Peer = spawn_link(fun() -> raw_server(LS, Settings) end),
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

raw_server(LS, Settings) ->
    {ok, S} = gen_tcp:accept(LS, 5000),
    {ok, ?PREFACE} = gen_tcp:recv(S, byte_size(?PREFACE), 5000),
    ok = gen_tcp:send(S, [h2_frame:encode(h2_frame:settings(Settings)),
                          h2_frame:encode(h2_frame:settings_ack())]),
    raw_server_loop(#{sock => S, buf => <<>>}, []).

raw_server_loop(Raw, Acc) ->
    {Frames, Raw1} = read_frames(Raw, fun(_) -> false end,
                                 erlang:monotonic_time(millisecond) + 50, []),
    Acc1 = Acc ++ Frames,
    receive
        {frames, From} -> From ! {frames, self(), Acc1}
    after 0 -> ok
    end,
    raw_server_loop(Raw1, Acc1).

%% {StreamId, Path} of every request the peer has received, in order, decoded
%% with one HPACK context.
request_paths(Peer) ->
    timer:sleep(150),
    Peer ! {frames, self()},
    Frames = receive {frames, Peer, F} -> F after 2000 -> error(no_frames) end,
    {Paths, _} = lists:foldl(fun({?HEADERS, _, Sid, Block}, {Acc, Dec}) ->
                                     {ok, Headers, Dec1} = h2_hpack:decode(Block, Dec),
                                     {[{Sid, proplists:get_value(<<":path">>, Headers)} | Acc], Dec1};
                                (_, AccDec) ->
                                     AccDec
                             end, {[], h2_hpack:new_context()}, Frames),
    lists:reverse(Paths).

flush() ->
    receive _ -> flush() after 0 -> ok end.

-endif.
