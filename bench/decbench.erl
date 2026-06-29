-module(decbench).
-export([run/1]).

%% Microbench HPACK decode. Two cases:
%%  realistic: a typical request header set, repeated (warm dynamic table).
%%  deep:      decode an indexed reference to the OLDEST dynamic entry with a
%%             table of N entries. This is the worst case for the old lists:nth
%%             lookup (O(N)); with the map representation it should be flat in N.
%% Usage: -run decbench run <iters>

run([ItersS]) ->
    Iters = list_to_integer(ItersS),
    realistic(Iters),
    deep(Iters, 30),
    deep(Iters, 120),
    halt(0).

realistic(Iters) ->
    Req = [{<<":method">>, <<"GET">>}, {<<":scheme">>, <<"https">>},
           {<<":path">>, <<"/api/v1/things?id=42">>},
           {<<":authority">>, <<"example.com">>},
           {<<"user-agent">>, <<"Mozilla/5.0 (compatible; bench/1.0)">>},
           {<<"accept">>, <<"application/json">>},
           {<<"accept-encoding">>, <<"gzip, deflate, br">>},
           {<<"cookie">>, <<"session=abcdef0123456789; theme=dark">>}],
    %% Pre-generate the wire blocks with an evolving encoder context (so later
    %% requests are indexed references), then time decode with an evolving
    %% decoder context.
    Blocks = gen_blocks(Req, Iters),
    T0 = erlang:monotonic_time(microsecond),
    _ = decode_all(Blocks, eh2_hpack:new_context(4096)),
    T1 = erlang:monotonic_time(microsecond),
    io:format("realistic request decode: ~.3f us/op~n", [(T1 - T0) / Iters]).

gen_blocks(Req, N) ->
    gen_blocks(Req, N, eh2_hpack:new_context(4096), []).
gen_blocks(_Req, 0, _Ctx, Acc) -> lists:reverse(Acc);
gen_blocks(Req, N, Ctx, Acc) ->
    {Block, Ctx1} = eh2_hpack:encode(Req, Ctx),
    gen_blocks(Req, N - 1, Ctx1, [Block | Acc]).

decode_all([], _Ctx) -> ok;
decode_all([B | Rest], Ctx) ->
    {ok, _Hdrs, Ctx1} = eh2_hpack:decode(B, Ctx),
    decode_all(Rest, Ctx1).

%% Build a decoder context holding N dynamic entries, then time decoding an
%% indexed reference to the oldest one (dynamic index = STATIC + N).
deep(Iters, N) ->
    %% Populate both encoder and decoder dynamic tables with N entries.
    {PopBlocks, _} = lists:foldl(
        fun(I, {Acc, Ctx}) ->
            H = [{<<"x-h-", (integer_to_binary(I))/binary>>,
                  <<"v-", (integer_to_binary(I))/binary>>}],
            {Block, Ctx1} = eh2_hpack:encode(H, Ctx),
            {[Block | Acc], Ctx1}
        end, {[], eh2_hpack:new_context(65536)}, lists:seq(1, N)),
    DecCtx = decode_all_ctx(lists:reverse(PopBlocks), eh2_hpack:new_context(65536)),
    %% Re-encode the FIRST header (now the oldest dynamic entry) -> indexed ref
    %% at depth N. Use a fresh encoder primed with the same N entries.
    {_, EncCtxPrimed} = lists:foldl(
        fun(I, {_, Ctx}) ->
            H = [{<<"x-h-", (integer_to_binary(I))/binary>>,
                  <<"v-", (integer_to_binary(I))/binary>>}],
            {_, Ctx1} = eh2_hpack:encode(H, Ctx),
            {ok, Ctx1}
        end, {ok, eh2_hpack:new_context(65536)}, lists:seq(1, N)),
    First = [{<<"x-h-1">>, <<"v-1">>}],
    {DeepBlock, _} = eh2_hpack:encode(First, EncCtxPrimed),
    T0 = erlang:monotonic_time(microsecond),
    deep_loop(DeepBlock, DecCtx, Iters),
    T1 = erlang:monotonic_time(microsecond),
    io:format("deep lookup (table=~p entries): ~.3f us/op~n",
              [N, (T1 - T0) / Iters]).

decode_all_ctx([], Ctx) -> Ctx;
decode_all_ctx([B | Rest], Ctx) ->
    {ok, _, Ctx1} = eh2_hpack:decode(B, Ctx),
    decode_all_ctx(Rest, Ctx1).

deep_loop(_Block, _Ctx, 0) -> ok;
deep_loop(Block, Ctx, N) ->
    {ok, _, _} = eh2_hpack:decode(Block, Ctx),
    deep_loop(Block, Ctx, N - 1).
