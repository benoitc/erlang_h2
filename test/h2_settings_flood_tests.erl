%% @doc SETTINGS flood (CVE-2019-9515, RFC 9113 §10.5): a peer that sends
%% SETTINGS frames without limit makes the endpoint write an ACK, merge the
%% settings and walk every stream for each one. Past a per-second cap the
%% connection is closed with GOAWAY(ENHANCE_YOUR_CALM); a handful of SETTINGS
%% frames is still accepted.
-module(h2_settings_flood_tests).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(ENHANCE_YOUR_CALM, 11).

settings_flood_test_() ->
    {setup,
     fun() -> {ok, _} = application:ensure_all_started(h2) end,
     fun(_) -> ok end,
     [{"a SETTINGS flood ends in GOAWAY(ENHANCE_YOUR_CALM)",
       {timeout, 30, fun flood/0}},
      {"a few SETTINGS frames are acked and requests still work",
       {timeout, 30, fun no_false_positive/0}}]}.

flood() ->
    {Ref, Sock} = connect(),
    try
        Settings = h2_frame:encode(h2_frame:settings([])),
        ok = gen_tcp:send(Sock, lists:duplicate(100, Settings)),
        #{goaway := Code, acks := Acks} = drain(Sock, deadline(3000)),
        ?assertEqual(?ENHANCE_YOUR_CALM, Code),
        ?assert(Acks =< 21)
    after
        close(Ref, Sock)
    end.

no_false_positive() ->
    {Ref, Sock} = connect(),
    try
        Settings = h2_frame:encode(h2_frame:settings([{initial_window_size, 65535}])),
        ok = gen_tcp:send(Sock, lists:duplicate(5, Settings)),
        ok = gen_tcp:send(Sock, request(1)),
        Seen = drain(Sock, deadline(1500)),
        ?assertEqual(undefined, maps:get(goaway, Seen)),
        %% 5 extra frames plus the one at the preface.
        ?assertEqual(6, maps:get(acks, Seen)),
        ?assert(maps:get(response, Seen))
    after
        close(Ref, Sock)
    end.

%% ---------------------------------------------------------------------------

connect() ->
    Handler = fun(Conn, Sid, _M, _P, _H) ->
                      h2:send_response(Conn, Sid, 200, []),
                      h2:send_data(Conn, Sid, <<>>, true)
              end,
    {ok, Ref} = h2:start_server(0, #{transport => tcp, handler => Handler}),
    {ok, Sock} = gen_tcp:connect("127.0.0.1", h2:server_port(Ref),
                                 [binary, {active, false}, {packet, raw}], 5000),
    ok = gen_tcp:send(Sock, [?PREFACE,
                             h2_frame:encode(h2_frame:settings([])),
                             h2_frame:encode(h2_frame:settings_ack())]),
    {Ref, Sock}.

request(StreamId) ->
    Headers = [{<<":method">>, <<"GET">>}, {<<":scheme">>, <<"http">>},
               {<<":path">>, <<"/">>}, {<<":authority">>, <<"127.0.0.1">>}],
    {Block, _} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    Len = byte_size(Block),
    %% HEADERS with END_STREAM | END_HEADERS.
    <<Len:24, 16#1:8, 16#5:8, 0:1, StreamId:31, Block/binary>>.

drain(Sock, Deadline) ->
    drain(Sock, <<>>, #{goaway => undefined, acks => 0, response => false}, Deadline).

drain(Sock, Buf, Acc, Deadline) ->
    case h2_frame:decode(Buf) of
        {ok, {goaway, _, Code, _}, Rest} ->
            drain(Sock, Rest, Acc#{goaway := Code}, Deadline);
        {ok, {settings_ack}, Rest} ->
            drain(Sock, Rest, maps:update_with(acks, fun(N) -> N + 1 end, Acc), Deadline);
        {ok, {headers, 1, _, _, _}, Rest} ->
            drain(Sock, Rest, Acc#{response := true}, Deadline);
        {ok, _, Rest} ->
            drain(Sock, Rest, Acc, Deadline);
        {error, _, Rest} ->
            drain(Sock, Rest, Acc, Deadline);
        _ ->
            T = Deadline - erlang:monotonic_time(millisecond),
            case T > 0 andalso gen_tcp:recv(Sock, 0, T) of
                {ok, Data} -> drain(Sock, <<Buf/binary, Data/binary>>, Acc, Deadline);
                _ -> Acc
            end
    end.

deadline(Ms) -> erlang:monotonic_time(millisecond) + Ms.

close(Ref, Sock) ->
    _ = gen_tcp:close(Sock),
    h2:stop_server(Ref).

-endif.
