%% @doc RFC 9113 §5.1.2 / §6.5.2: with `notify_stream_available => true' a
%% client refused with `max_streams_exceeded' is told once, through
%% `{h2, Conn, stream_available}', when a stream slot frees: a stream closes
%% or the peer raises SETTINGS_MAX_CONCURRENT_STREAMS. A raw gen_tcp h2c peer
%% built on h2_frame advertises a limit of 1 and sends the frames each case
%% asks for. Absence is checked behind a PING barrier, never a sleep.
-module(h2_stream_available_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).

stream_available_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"refused, then a stream ends: one notice",
       {timeout, 30, fun stream_end_notifies/0}},
      {"refused, then the peer raises the limit: one notice",
       {timeout, 30, fun settings_raise_notifies/0}},
      {"no refusal: no notice when streams end",
       {timeout, 30, fun no_refusal_no_notice/0}},
      {"limit lowered to 0: no notice until active < limit",
       {timeout, 30, fun lowered_limit_waits/0}},
      {"GOAWAY while blocked: no notice",
       {timeout, 30, fun goaway_no_notice/0}},
      {"option off: no notice, same replies",
       {timeout, 30, fun option_off/0}}]}.

stream_end_notifies() ->
    {Conn, Peer, Port} = setup(true),
    {ok, Sid} = request(Conn, Port),
    wait_headers(Sid),
    ?assertEqual({error, max_streams_exceeded}, request(Conn, Port)),
    ?assertEqual({error, max_streams_exceeded}, request(Conn, Port)),
    respond(Peer, Sid),
    wait_stream_available(Conn),
    barrier(Conn, Peer),
    assert_no_notice(Conn),
    ?assertMatch({ok, _}, request(Conn, Port)),
    cleanup(Conn, Peer).

settings_raise_notifies() ->
    {Conn, Peer, Port} = setup(true),
    {ok, Sid} = request(Conn, Port),
    wait_headers(Sid),
    ?assertEqual({error, max_streams_exceeded}, request_headers(Conn, Port)),
    send(Peer, h2_frame:settings([{max_concurrent_streams, 2}])),
    wait_stream_available(Conn),
    barrier(Conn, Peer),
    assert_no_notice(Conn),
    ?assertMatch({ok, _}, request_headers(Conn, Port)),
    cleanup(Conn, Peer).

no_refusal_no_notice() ->
    {Conn, Peer, Port} = setup(true),
    lists:foreach(fun(_) ->
        {ok, Sid} = request(Conn, Port),
        wait_headers(Sid),
        respond(Peer, Sid),
        wait_response(Conn, Sid)
    end, [1, 2, 3]),
    send(Peer, h2_frame:settings([{max_concurrent_streams, 5}])),
    barrier(Conn, Peer),
    assert_no_notice(Conn),
    cleanup(Conn, Peer).

lowered_limit_waits() ->
    {Conn, Peer, Port} = setup(true),
    {ok, Sid} = request(Conn, Port),
    wait_headers(Sid),
    ?assertEqual({error, max_streams_exceeded}, request(Conn, Port)),
    send(Peer, h2_frame:settings([{max_concurrent_streams, 0}])),
    respond(Peer, Sid),
    wait_response(Conn, Sid),
    barrier(Conn, Peer),
    assert_no_notice(Conn),
    send(Peer, h2_frame:settings([{max_concurrent_streams, 1}])),
    wait_stream_available(Conn),
    barrier(Conn, Peer),
    assert_no_notice(Conn),
    ?assertMatch({ok, _}, request(Conn, Port)),
    cleanup(Conn, Peer).

goaway_no_notice() ->
    {Conn, Peer, Port} = setup(true),
    {ok, Sid} = request(Conn, Port),
    wait_headers(Sid),
    ?assertEqual({error, max_streams_exceeded}, request(Conn, Port)),
    send(Peer, h2_frame:goaway(Sid, no_error, <<>>)),
    receive {h2, Conn, {goaway, Sid, no_error}} -> ok
    after 5000 -> error(no_goaway) end,
    respond(Peer, Sid),
    wait_response(Conn, Sid),
    send(Peer, h2_frame:settings([{max_concurrent_streams, 5}])),
    barrier(Conn, Peer),
    assert_no_notice(Conn),
    cleanup(Conn, Peer).

option_off() ->
    {Conn, Peer, Port} = setup(false),
    {ok, Sid} = request(Conn, Port),
    wait_headers(Sid),
    ?assertEqual({error, max_streams_exceeded}, request(Conn, Port)),
    ?assertEqual({error, max_streams_exceeded}, request_headers(Conn, Port)),
    respond(Peer, Sid),
    wait_response(Conn, Sid),
    send(Peer, h2_frame:settings([{max_concurrent_streams, 5}])),
    barrier(Conn, Peer),
    assert_no_notice(Conn),
    ?assertMatch({ok, _}, request(Conn, Port)),
    cleanup(Conn, Peer).

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

setup(Notify) ->
    process_flag(trap_exit, true),
    flush(),
    {Port, Peer} = start_peer(self()),
    Opts = case Notify of
        true -> #{transport => tcp, notify_stream_available => true};
        false -> #{transport => tcp}
    end,
    {ok, Conn} = h2:connect("127.0.0.1", Port, Opts),
    ok = h2:wait_connected(Conn),
    %% The peer SETTINGS (limit 1) is applied before the barrier PING is acked.
    barrier(Conn, Peer),
    1 = maps:get(max_concurrent_streams, h2:get_peer_settings(Conn)),
    {Conn, Peer, Port}.

request(Conn, Port) ->
    h2:request(Conn, <<"GET">>, <<"/">>,
               [{<<"host">>, authority(Port)}]).

request_headers(Conn, Port) ->
    h2:request(Conn, [{<<":method">>, <<"GET">>},
                      {<<":path">>, <<"/">>},
                      {<<":scheme">>, <<"http">>},
                      {<<":authority">>, authority(Port)}],
               #{end_stream => true}).

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

send(Peer, Frame) ->
    Peer ! {send, Frame},
    ok.

respond(Peer, Sid) ->
    Peer ! {respond, Sid},
    ok.

%% The peer sends PING after every frame queued so far; once the client has
%% acked it, those frames are processed. The sync call then orders any message
%% the connection sent before it ahead of the reply.
barrier(Conn, Peer) ->
    Ref = make_ref(),
    Peer ! {barrier, self(), Ref},
    receive {barrier_done, Ref} -> ok
    after 5000 -> error(no_barrier) end,
    _ = h2:get_peer_settings(Conn),
    ok.

wait_headers(Sid) ->
    receive {headers, Sid} -> ok
    after 5000 -> error({no_headers, Sid}) end.

wait_response(Conn, Sid) ->
    receive {h2, Conn, {response, Sid, 200, _}} -> ok
    after 5000 -> error({no_response, Sid}) end.

wait_stream_available(Conn) ->
    receive {h2, Conn, stream_available} -> ok
    after 5000 -> error(no_stream_available) end.

assert_no_notice(Conn) ->
    receive {h2, Conn, stream_available} -> error(unexpected_stream_available)
    after 0 -> ok end.

cleanup(Conn, Peer) ->
    try h2:close(Conn) catch exit:_ -> ok end,
    Peer ! stop,
    receive {'EXIT', Peer, _} -> ok after 5000 -> error(peer_still_up) end,
    flush().

flush() ->
    receive _ -> flush() after 0 -> ok end.

%% ---------------------------------------------------------------------------
%% Raw h2c peer: advertises SETTINGS_MAX_CONCURRENT_STREAMS = 1, reports each
%% HEADERS it receives, and sends what the test asks for.
%% ---------------------------------------------------------------------------

start_peer(TestPid) ->
    {ok, LSock} = gen_tcp:listen(0, [binary, {active, false}, {packet, raw},
                                     {ip, {127, 0, 0, 1}}, {reuseaddr, true}]),
    {ok, Port} = inet:port(LSock),
    Pid = spawn_link(fun() -> serve(LSock, TestPid) end),
    {Port, Pid}.

serve(LSock, TestPid) ->
    {ok, Sock} = gen_tcp:accept(LSock, 5000),
    gen_tcp:close(LSock),
    Rest = read_preface(Sock, <<>>),
    out(Sock, h2_frame:settings([{max_concurrent_streams, 1}])),
    ok = inet:setopts(Sock, [{active, true}]),
    loop(#{sock => Sock, buf => Rest, test => TestPid,
           hpack => h2_hpack:new_context(), barriers => #{}}).

read_preface(Sock, Buf) when byte_size(Buf) < byte_size(?PREFACE) ->
    {ok, Data} = gen_tcp:recv(Sock, 0, 5000),
    read_preface(Sock, <<Buf/binary, Data/binary>>);
read_preface(_Sock, Buf) ->
    Size = byte_size(?PREFACE),
    <<Preface:Size/binary, Rest/binary>> = Buf,
    ?PREFACE = Preface,
    Rest.

loop(#{sock := Sock} = S) ->
    S1 = decode_all(S),
    receive
        stop ->
            gen_tcp:close(Sock);
        {tcp, Sock, Data} ->
            loop(S1#{buf := <<(maps:get(buf, S1))/binary, Data/binary>>});
        {tcp_closed, Sock} ->
            ok;
        {send, Frame} ->
            out(Sock, Frame),
            loop(S1);
        {respond, Sid} ->
            {Block, Ctx} = h2_hpack:encode([{<<":status">>, <<"200">>}],
                                           maps:get(hpack, S1)),
            out(Sock, h2_frame:headers(Sid, Block, true)),
            loop(S1#{hpack := Ctx});
        {barrier, From, Ref} ->
            Data = <<(erlang:unique_integer([positive])):64>>,
            out(Sock, h2_frame:ping(Data)),
            loop(S1#{barriers := maps:put(Data, {From, Ref},
                                          maps:get(barriers, S1))})
    end.

decode_all(#{buf := Buf} = S) ->
    case h2_frame:decode(Buf) of
        {ok, Frame, Rest} -> decode_all(handle(Frame, S#{buf := Rest}));
        {more, _} -> S
    end.

handle({settings, _}, #{sock := Sock} = S) ->
    out(Sock, h2_frame:settings_ack()),
    S;
handle(Frame, #{test := TestPid} = S) when element(1, Frame) =:= headers ->
    TestPid ! {headers, element(2, Frame)},
    S;
handle({ping_ack, Data}, #{barriers := B} = S) ->
    {From, Ref} = maps:get(Data, B),
    From ! {barrier_done, Ref},
    S#{barriers := maps:remove(Data, B)};
handle(_Frame, S) ->
    S.

out(Sock, Frame) ->
    ok = gen_tcp:send(Sock, h2_frame:encode(Frame)).

-endif.
