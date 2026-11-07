%% @doc MadeYouReset (CVE-2025-8671): a peer that keeps breaking the protocol
%% so the server resets the stream frees the stream's MAX_CONCURRENT_STREAMS
%% slot while the handler keeps running, bypassing the concurrency limit. The
%% server now caps the resets it sends per second and drops the connection with
%% GOAWAY(ENHANCE_YOUR_CALM) past the cap.
-module(h2_made_you_reset_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(ENHANCE_YOUR_CALM, 11).
-define(MAX_CONCURRENT, 100).
%% Enough streams to blow well past the per-second reset cap.
-define(STREAMS, 400).

made_you_reset_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"WINDOW_UPDATE 0 after a request is capped and ends in GOAWAY",
       {timeout, 30, fun() -> attack(fun wu_zero/2) end}},
      {"wrong-length PRIORITY after a request is capped",
       {timeout, 30, fun() -> attack(fun priority_bad_len/2) end}},
      {"stream-window overflow after a request is capped",
       {timeout, 30, fun() -> attack(fun wu_overflow/2) end}},
      {"a burst of real requests is not dropped",
       {timeout, 30, fun no_false_positive/0}}]}.

%% Each primitive sends a complete request, then one frame that makes the
%% server reset the stream. Concurrency must stay at the advertised limit and
%% the server must answer with GOAWAY(ENHANCE_YOUR_CALM).
attack(Primitive) ->
    Counter = atomics:new(2, []),
    {Ref, Sock} = connect(Counter),
    try
        _ = send_requests(Sock, ?STREAMS, Primitive),
        {Resets, Goaway} = drain(Sock, <<>>, 0, undefined, deadline(5000)),
        ?assert(atomics:get(Counter, 2) =< ?MAX_CONCURRENT + 1),
        ?assert(Resets > 0),
        ?assertEqual(?ENHANCE_YOUR_CALM, Goaway)
    after
        close(Ref, Sock)
    end.

%% A client may legitimately pipeline more than MAX_CONCURRENT_STREAMS
%% requests; the excess is refused with REFUSED_STREAM but the connection
%% stays up (no GOAWAY).
no_false_positive() ->
    Counter = atomics:new(2, []),
    {Ref, Sock} = connect(Counter),
    try
        _ = send_requests(Sock, ?STREAMS, fun(_, Ctx) -> {<<>>, Ctx} end),
        {_Resets, Goaway} = drain(Sock, <<>>, 0, undefined, deadline(3000)),
        ?assert(atomics:get(Counter, 2) =< ?MAX_CONCURRENT + 1),
        ?assertEqual(undefined, Goaway)
    after
        close(Ref, Sock)
    end.

%% ---------------------------------------------------------------------------

%% Counter index 1 is the live in-flight handler count; index 2 is its peak,
%% updated with a compare-exchange so concurrent handlers don't lose an update.
connect(Counter) ->
    Handler = fun(Conn, Sid, _M, _P, _H) ->
                      N = atomics:add_get(Counter, 1, 1),
                      bump_peak(Counter, N),
                      timer:sleep(1500),
                      atomics:sub(Counter, 1, 1),
                      h2:send_response(Conn, Sid, 200, []),
                      h2:send_data(Conn, Sid, <<>>, true)
              end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler,
                                     settings => #{max_concurrent_streams => ?MAX_CONCURRENT}}),
    {ok, Sock} = gen_tcp:connect("127.0.0.1", h2:server_port(Ref),
                                 [binary, {active, false}, {packet, raw}], 5000),
    ok = gen_tcp:send(Sock, [?PREFACE,
                             h2_frame:encode(h2_frame:settings([])),
                             h2_frame:encode(h2_frame:settings_ack())]),
    {Ref, Sock}.

bump_peak(Counter, N) ->
    Peak = atomics:get(Counter, 2),
    case N > Peak of
        true ->
            case atomics:compare_exchange(Counter, 2, Peak, N) of
                ok -> ok;
                _ -> bump_peak(Counter, N)
            end;
        false ->
            ok
    end.

send_requests(Sock, N, Primitive) ->
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>},
               {<<":scheme">>, <<"http">>}, {<<":authority">>, <<"x">>}],
    lists:foldl(
      fun(I, Ctx) ->
              Sid = 2 * I - 1,
              {Block, Ctx1} = h2_hpack:encode(Headers, Ctx),
              {Extra, Ctx2} = Primitive(Sid, Ctx1),
              ok = gen_tcp:send(Sock, [h2_frame:encode(h2_frame:headers(Sid, Block, true)),
                                       Extra]),
              Ctx2
      end, h2_hpack:new_context(), lists:seq(1, N)).

wu_zero(Sid, Ctx) ->
    {<<4:24, 8:8, 0:8, 0:1, Sid:31, 0:32>>, Ctx}.

priority_bad_len(Sid, Ctx) ->
    %% PRIORITY (type 2) with length 2 instead of 5.
    {<<2:24, 2:8, 0:8, 0:1, Sid:31, 0:16>>, Ctx}.

wu_overflow(Sid, Ctx) ->
    {h2_frame:encode(h2_frame:window_update(Sid, 2147483647)), Ctx}.

drain(Sock, Buf, Resets, Goaway, Deadline) ->
    case h2_frame:decode(Buf) of
        {ok, {rst_stream, _, _}, Rest} ->
            drain(Sock, Rest, Resets + 1, Goaway, Deadline);
        {ok, {goaway, _, Code, _}, Rest} ->
            drain(Sock, Rest, Resets, Code, Deadline);
        {ok, _, Rest} ->
            drain(Sock, Rest, Resets, Goaway, Deadline);
        {error, _, Rest} ->
            drain(Sock, Rest, Resets, Goaway, Deadline);
        _ ->
            T = Deadline - erlang:monotonic_time(millisecond),
            case T > 0 andalso gen_tcp:recv(Sock, 0, T) of
                {ok, Data} -> drain(Sock, <<Buf/binary, Data/binary>>, Resets, Goaway, Deadline);
                _ -> {Resets, Goaway}
            end
    end.

deadline(Ms) -> erlang:monotonic_time(millisecond) + Ms.

close(Ref, Sock) ->
    _ = gen_tcp:close(Sock),
    h2:stop_server(Ref).

-endif.
