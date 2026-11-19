%% @doc A bounded memory of how recently closed streams ended.
%%
%% RFC 9113 §5.1 treats a frame that arrives on a closed stream differently
%% depending on how the stream closed: after END_STREAM it is a connection
%% error, after RST_STREAM a stream error. A connection therefore has to
%% remember closed streams for a while, and a peer must not be able to make
%% that memory grow without limit.
%%
%% Two layers, both first in first out:
%% <ul>
%% <li>the ids of the last 100 closed streams, whose full records the
%%     connection still keeps in its stream table. `add/3' returns the ids
%%     that fall out, for the caller to drop from that table;</li>
%% <li>the close reason of the last 10,000 closed streams, kept here.</li>
%% </ul>
%%
%% Past both, `reason/2' answers `unknown' and the connection falls back to
%% the stream id ranges it has used.
%%
%% Internal: used by `h2_connection' only.
-module(h2_closed_streams).

-export([new/0, add/3, reason/2, no_content/2]).

-export_type([t/0, reason/0]).

%% How many closed streams keep their full record in the stream table.
-define(RECORDS_LIMIT, 100).
%% How many closed streams keep their close reason.
-define(REASONS_LIMIT, 10000).

-record(closed, {
    records = queue:new() :: queue:queue(non_neg_integer()),
    records_count = 0 :: non_neg_integer(),
    reasons = #{} :: #{non_neg_integer() => reason()},
    reasons_q = queue:new() :: queue:queue(non_neg_integer()),
    reasons_count = 0 :: non_neg_integer()
}).

%% `no_content': closed by END_STREAM after a response with no content was
%% sent. It reads as `end_stream' through `reason/2'.
-type reason() :: end_stream | no_content | rst.
-opaque t() :: #closed{}.

-spec new() -> t().
new() ->
    #closed{}.

%% @doc Remember that StreamId closed with Reason. Returns the stream ids whose
%% full record is now past the limit and should be dropped from the stream
%% table.
-spec add(non_neg_integer(), reason(), t()) -> {[non_neg_integer()], t()}.
add(StreamId, Reason, #closed{records = Q, records_count = N,
                              reasons = Reasons, reasons_q = RQ,
                              reasons_count = RN} = Closed) ->
    {Evicted, Q1, N1} = evict_records(queue:in(StreamId, Q), N + 1, []),
    {Reasons1, RQ1, RN1} = evict_reasons(maps:put(StreamId, Reason, Reasons),
                                         queue:in(StreamId, RQ), RN + 1),
    {Evicted, Closed#closed{records = Q1, records_count = N1,
                            reasons = Reasons1, reasons_q = RQ1,
                            reasons_count = RN1}}.

%% @doc How StreamId closed, or `unknown' when it is not remembered.
-spec reason(non_neg_integer(), t()) -> end_stream | rst | unknown.
reason(StreamId, #closed{reasons = Reasons}) ->
    case maps:get(StreamId, Reasons, unknown) of
        no_content -> end_stream;
        Reason     -> Reason
    end.

%% @doc True when StreamId closed after a response with no content was sent.
-spec no_content(non_neg_integer(), t()) -> boolean().
no_content(StreamId, #closed{reasons = Reasons}) ->
    maps:get(StreamId, Reasons, unknown) =:= no_content.

evict_records(Q, N, Acc) when N =< ?RECORDS_LIMIT ->
    {lists:reverse(Acc), Q, N};
evict_records(Q, N, Acc) ->
    {{value, OldId}, Q1} = queue:out(Q),
    evict_records(Q1, N - 1, [OldId | Acc]).

evict_reasons(Reasons, Q, N) when N =< ?REASONS_LIMIT ->
    {Reasons, Q, N};
evict_reasons(Reasons, Q, N) ->
    {{value, OldId}, Q1} = queue:out(Q),
    evict_reasons(maps:remove(OldId, Reasons), Q1, N - 1).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

add_all(Ids, Reason, Closed0) ->
    lists:foldl(fun(Id, {Acc, C}) ->
        {Evicted, C1} = add(Id, Reason, C),
        {Acc ++ Evicted, C1}
    end, {[], Closed0}, Ids).

reason_test_() ->
    {[], C} = add_all([1, 3, 5], end_stream, new()),
    {[], C1} = add(7, rst, C),
    {[], C2} = add(9, no_content, C1),
    [?_assertEqual(end_stream, reason(1, C2)),
     ?_assertEqual(rst, reason(7, C2)),
     %% no_content reads as end_stream, and is told apart by no_content/2.
     ?_assertEqual(end_stream, reason(9, C2)),
     ?_assert(no_content(9, C2)),
     ?_assertNot(no_content(1, C2)),
     ?_assertEqual(unknown, reason(11, C2)),
     ?_assertNot(no_content(11, C2))].

records_limit_test_() ->
    Ids = lists:seq(1, 2 * ?RECORDS_LIMIT + 5, 2),
    {Evicted, C} = add_all(Ids, rst, new()),
    Over = length(Ids) - ?RECORDS_LIMIT,
    [%% Nothing is evicted until the limit is passed.
     ?_assertMatch({[], _}, add_all(lists:seq(1, 2 * ?RECORDS_LIMIT, 2), rst, new())),
     %% Then the oldest ids come back, oldest first.
     ?_assertEqual(lists:sublist(Ids, Over), Evicted),
     ?_assertEqual(?RECORDS_LIMIT, C#closed.records_count),
     %% Their reason is still known.
     ?_assertEqual(rst, reason(hd(Ids), C))].

reasons_limit_test_() ->
    Ids = lists:seq(1, 2 * (?REASONS_LIMIT + 3), 2),
    {_, C} = add_all(Ids, end_stream, new()),
    [?_assertEqual(?REASONS_LIMIT, C#closed.reasons_count),
     ?_assertEqual(?REASONS_LIMIT, map_size(C#closed.reasons)),
     %% The three oldest are forgotten, the rest are kept.
     ?_assertEqual([unknown, unknown, unknown, end_stream],
                   [reason(Id, C) || Id <- lists:sublist(Ids, 4)]),
     ?_assertEqual(end_stream, reason(lists:last(Ids), C))].

-endif.
