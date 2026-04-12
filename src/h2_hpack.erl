%% @doc HPACK Header Compression for HTTP/2 (RFC 7541)
%%
%% This module provides HPACK encoding and decoding for HTTP/2 headers.
%%
%% HPACK uses:
%% - Static table: 61 predefined header name/value pairs
%% - Dynamic table: Runtime-populated entries (FIFO eviction)
%% - Huffman coding: Optional string compression
%% - Integer encoding: Variable-length prefix encoding
%%
-module(h2_hpack).

-export([new_context/0, new_context/1]).
-export([encode/2, decode/2]).
-export([set_max_table_size/2, get_max_table_size/1]).
-export([encode_integer/2, decode_integer/2]).
-export([huffman_encode/1, huffman_decode/1]).

-include("h2.hrl").
-include("h2_hpack_huffman.hrl").

%% Context record for encoder/decoder state
-record(hpack_context, {
    max_table_size = ?DEFAULT_HEADER_TABLE_SIZE :: non_neg_integer(),
    table_size = 0 :: non_neg_integer(),
    dynamic_table = [] :: [{binary(), binary()}]
}).

-type context() :: #hpack_context{}.
-type header() :: {binary(), binary()}.
-type headers() :: [header()].

-export_type([context/0, header/0, headers/0]).

%% Static table (RFC 7541 Appendix A)
-define(STATIC_TABLE, [
    {<<":authority">>, <<>>},           %% 1
    {<<":method">>, <<"GET">>},         %% 2
    {<<":method">>, <<"POST">>},        %% 3
    {<<":path">>, <<"/">>},             %% 4
    {<<":path">>, <<"/index.html">>},   %% 5
    {<<":scheme">>, <<"http">>},        %% 6
    {<<":scheme">>, <<"https">>},       %% 7
    {<<":status">>, <<"200">>},         %% 8
    {<<":status">>, <<"204">>},         %% 9
    {<<":status">>, <<"206">>},         %% 10
    {<<":status">>, <<"304">>},         %% 11
    {<<":status">>, <<"400">>},         %% 12
    {<<":status">>, <<"404">>},         %% 13
    {<<":status">>, <<"500">>},         %% 14
    {<<"accept-charset">>, <<>>},       %% 15
    {<<"accept-encoding">>, <<"gzip, deflate">>},  %% 16
    {<<"accept-language">>, <<>>},      %% 17
    {<<"accept-ranges">>, <<>>},        %% 18
    {<<"accept">>, <<>>},               %% 19
    {<<"access-control-allow-origin">>, <<>>},  %% 20
    {<<"age">>, <<>>},                  %% 21
    {<<"allow">>, <<>>},                %% 22
    {<<"authorization">>, <<>>},        %% 23
    {<<"cache-control">>, <<>>},        %% 24
    {<<"content-disposition">>, <<>>},  %% 25
    {<<"content-encoding">>, <<>>},     %% 26
    {<<"content-language">>, <<>>},     %% 27
    {<<"content-length">>, <<>>},       %% 28
    {<<"content-location">>, <<>>},     %% 29
    {<<"content-range">>, <<>>},        %% 30
    {<<"content-type">>, <<>>},         %% 31
    {<<"cookie">>, <<>>},               %% 32
    {<<"date">>, <<>>},                 %% 33
    {<<"etag">>, <<>>},                 %% 34
    {<<"expect">>, <<>>},               %% 35
    {<<"expires">>, <<>>},              %% 36
    {<<"from">>, <<>>},                 %% 37
    {<<"host">>, <<>>},                 %% 38
    {<<"if-match">>, <<>>},             %% 39
    {<<"if-modified-since">>, <<>>},    %% 40
    {<<"if-none-match">>, <<>>},        %% 41
    {<<"if-range">>, <<>>},             %% 42
    {<<"if-unmodified-since">>, <<>>},  %% 43
    {<<"last-modified">>, <<>>},        %% 44
    {<<"link">>, <<>>},                 %% 45
    {<<"location">>, <<>>},             %% 46
    {<<"max-forwards">>, <<>>},         %% 47
    {<<"proxy-authenticate">>, <<>>},   %% 48
    {<<"proxy-authorization">>, <<>>},  %% 49
    {<<"range">>, <<>>},                %% 50
    {<<"referer">>, <<>>},              %% 51
    {<<"refresh">>, <<>>},              %% 52
    {<<"retry-after">>, <<>>},          %% 53
    {<<"server">>, <<>>},               %% 54
    {<<"set-cookie">>, <<>>},           %% 55
    {<<"strict-transport-security">>, <<>>},  %% 56
    {<<"transfer-encoding">>, <<>>},    %% 57
    {<<"user-agent">>, <<>>},           %% 58
    {<<"vary">>, <<>>},                 %% 59
    {<<"via">>, <<>>},                  %% 60
    {<<"www-authenticate">>, <<>>}      %% 61
]).

%% @doc Create a new HPACK context with default settings.
-spec new_context() -> context().
new_context() ->
    new_context(?DEFAULT_HEADER_TABLE_SIZE).

%% @doc Create a new HPACK context with specified max table size.
-spec new_context(non_neg_integer()) -> context().
new_context(MaxTableSize) ->
    #hpack_context{max_table_size = MaxTableSize}.

%% @doc Set the maximum dynamic table size.
-spec set_max_table_size(non_neg_integer(), context()) -> context().
set_max_table_size(Size, Ctx) ->
    Ctx1 = Ctx#hpack_context{max_table_size = Size},
    evict_to_fit(0, Ctx1).

%% @doc Get the maximum dynamic table size.
-spec get_max_table_size(context()) -> non_neg_integer().
get_max_table_size(#hpack_context{max_table_size = Size}) ->
    Size.

%% @doc Encode a list of headers.
-spec encode(headers(), context()) -> {binary(), context()}.
encode(Headers, Ctx) ->
    encode_headers(Headers, Ctx, <<>>).

encode_headers([], Ctx, Acc) ->
    {Acc, Ctx};
encode_headers([{Name, Value}|Rest], Ctx, Acc) ->
    {Encoded, Ctx1} = encode_header(Name, Value, Ctx),
    encode_headers(Rest, Ctx1, <<Acc/binary, Encoded/binary>>).

encode_header(Name, Value, Ctx) ->
    %% Try to find an exact match in static or dynamic table
    case find_header(Name, Value, Ctx) of
        {indexed, Index} ->
            %% Indexed Header Field (Section 6.1)
            Encoded = encode_indexed(Index),
            {Encoded, Ctx};
        {name_indexed, Index} ->
            %% Literal Header with Incremental Indexing (Section 6.2.1)
            {Encoded, Ctx1} = encode_literal_indexed(Index, Value, Ctx),
            {Encoded, Ctx1};
        not_found ->
            %% Literal Header with Incremental Indexing, new name
            {Encoded, Ctx1} = encode_literal_new(Name, Value, Ctx),
            {Encoded, Ctx1}
    end.

encode_indexed(Index) ->
    encode_integer(Index, 7, 2#1).

encode_literal_indexed(NameIndex, Value, Ctx) ->
    IndexBin = encode_integer(NameIndex, 6, 2#01),
    ValueBin = encode_string(Value),
    Encoded = <<IndexBin/binary, ValueBin/binary>>,
    Ctx1 = add_to_dynamic_table(lookup_name(NameIndex, Ctx), Value, Ctx),
    {Encoded, Ctx1}.

encode_literal_new(Name, Value, Ctx) ->
    IndexBin = encode_integer(0, 6, 2#01),
    NameBin = encode_string(Name),
    ValueBin = encode_string(Value),
    Encoded = <<IndexBin/binary, NameBin/binary, ValueBin/binary>>,
    Ctx1 = add_to_dynamic_table(Name, Value, Ctx),
    {Encoded, Ctx1}.

encode_string(Str) ->
    %% Try Huffman encoding, use if shorter
    Huffman = huffman_encode(Str),
    if
        byte_size(Huffman) < byte_size(Str) ->
            Len = encode_integer(byte_size(Huffman), 7, 2#1),
            <<Len/binary, Huffman/binary>>;
        true ->
            Len = encode_integer(byte_size(Str), 7, 2#0),
            <<Len/binary, Str/binary>>
    end.

%% @doc Decode a HPACK-encoded header block.
-spec decode(binary(), context()) -> {ok, headers(), context()} | {error, term()}.
decode(Bin, Ctx) ->
    decode_headers(Bin, Ctx, []).

decode_headers(<<>>, Ctx, Acc) ->
    {ok, lists:reverse(Acc), Ctx};
decode_headers(<<2#1:1, _/bits>> = Bin, Ctx, Acc) ->
    %% Indexed Header Field (Section 6.1)
    case decode_integer(Bin, 7) of
        {ok, 0, _} ->
            {error, invalid_index};
        {ok, Index, Rest} ->
            case lookup(Index, Ctx) of
                {ok, Name, Value} ->
                    decode_headers(Rest, Ctx, [{Name, Value}|Acc]);
                error ->
                    {error, {invalid_index, Index}}
            end;
        {error, _} = Err ->
            Err
    end;
decode_headers(<<2#01:2, _/bits>> = Bin, Ctx, Acc) ->
    %% Literal Header with Incremental Indexing (Section 6.2.1)
    case decode_literal(Bin, 6, Ctx) of
        {ok, Name, Value, Rest, Ctx1} ->
            Ctx2 = add_to_dynamic_table(Name, Value, Ctx1),
            decode_headers(Rest, Ctx2, [{Name, Value}|Acc]);
        {error, _} = Err ->
            Err
    end;
decode_headers(<<2#0000:4, _/bits>> = Bin, Ctx, Acc) ->
    %% Literal Header without Indexing (Section 6.2.2)
    case decode_literal(Bin, 4, Ctx) of
        {ok, Name, Value, Rest, Ctx1} ->
            decode_headers(Rest, Ctx1, [{Name, Value}|Acc]);
        {error, _} = Err ->
            Err
    end;
decode_headers(<<2#0001:4, _/bits>> = Bin, Ctx, Acc) ->
    %% Literal Header Never Indexed (Section 6.2.3)
    case decode_literal(Bin, 4, Ctx) of
        {ok, Name, Value, Rest, Ctx1} ->
            decode_headers(Rest, Ctx1, [{Name, Value}|Acc]);
        {error, _} = Err ->
            Err
    end;
decode_headers(<<2#001:3, _/bits>> = Bin, Ctx, Acc) ->
    %% Dynamic Table Size Update (Section 6.3)
    case decode_integer(Bin, 5) of
        {ok, Size, Rest} ->
            Ctx1 = set_max_table_size(Size, Ctx),
            decode_headers(Rest, Ctx1, Acc);
        {error, _} = Err ->
            Err
    end.

decode_literal(Bin, Prefix, Ctx) ->
    case decode_integer(Bin, Prefix) of
        {ok, 0, Rest} ->
            %% New name
            case decode_string(Rest) of
                {ok, Name, Rest1} ->
                    case decode_string(Rest1) of
                        {ok, Value, Rest2} ->
                            {ok, Name, Value, Rest2, Ctx};
                        {error, _} = Err ->
                            Err
                    end;
                {error, _} = Err ->
                    Err
            end;
        {ok, Index, Rest} ->
            %% Indexed name
            case lookup_name(Index, Ctx) of
                error ->
                    {error, {invalid_index, Index}};
                Name ->
                    case decode_string(Rest) of
                        {ok, Value, Rest1} ->
                            {ok, Name, Value, Rest1, Ctx};
                        {error, _} = Err ->
                            Err
                    end
            end;
        {error, _} = Err ->
            Err
    end.

decode_string(<<2#1:1, _/bits>> = Bin) ->
    %% Huffman encoded
    case decode_integer(Bin, 7) of
        {ok, Len, Rest} when byte_size(Rest) >= Len ->
            <<Huffman:Len/binary, Rest1/binary>> = Rest,
            case huffman_decode(Huffman) of
                {ok, Str} -> {ok, Str, Rest1};
                {error, _} = Err -> Err
            end;
        {ok, Len, _} ->
            {error, {incomplete_string, Len}};
        {error, _} = Err ->
            Err
    end;
decode_string(<<2#0:1, _/bits>> = Bin) ->
    %% Raw string
    case decode_integer(Bin, 7) of
        {ok, Len, Rest} when byte_size(Rest) >= Len ->
            <<Str:Len/binary, Rest1/binary>> = Rest,
            {ok, Str, Rest1};
        {ok, Len, _} ->
            {error, {incomplete_string, Len}};
        {error, _} = Err ->
            Err
    end.

%% Table operations

find_header(Name, Value, Ctx) ->
    case find_in_static(Name, Value) of
        {indexed, _} = Found -> Found;
        {name_indexed, _} = Found ->
            %% Check dynamic table for exact match
            case find_in_dynamic(Name, Value, Ctx) of
                {indexed, _} = DFound -> DFound;
                _ -> Found
            end;
        not_found ->
            find_in_dynamic(Name, Value, Ctx)
    end.

find_in_static(Name, Value) ->
    find_in_static(Name, Value, ?STATIC_TABLE, 1, not_found).

find_in_static(_Name, _Value, [], _Index, NameMatch) ->
    NameMatch;
find_in_static(Name, Value, [{Name, Value}|_], Index, _NameMatch) ->
    {indexed, Index};
find_in_static(Name, Value, [{Name, _}|Rest], Index, not_found) ->
    find_in_static(Name, Value, Rest, Index + 1, {name_indexed, Index});
find_in_static(Name, Value, [_|Rest], Index, NameMatch) ->
    find_in_static(Name, Value, Rest, Index + 1, NameMatch).

find_in_dynamic(Name, Value, #hpack_context{dynamic_table = DynTable}) ->
    find_in_dynamic(Name, Value, DynTable, ?HPACK_STATIC_TABLE_SIZE + 1, not_found).

find_in_dynamic(_Name, _Value, [], _Index, NameMatch) ->
    NameMatch;
find_in_dynamic(Name, Value, [{Name, Value}|_], Index, _NameMatch) ->
    {indexed, Index};
find_in_dynamic(Name, Value, [{Name, _}|Rest], Index, not_found) ->
    find_in_dynamic(Name, Value, Rest, Index + 1, {name_indexed, Index});
find_in_dynamic(Name, Value, [_|Rest], Index, NameMatch) ->
    find_in_dynamic(Name, Value, Rest, Index + 1, NameMatch).

lookup(Index, _Ctx) when Index >= 1, Index =< ?HPACK_STATIC_TABLE_SIZE ->
    {Name, Value} = lists:nth(Index, ?STATIC_TABLE),
    {ok, Name, Value};
lookup(Index, #hpack_context{dynamic_table = DynTable}) ->
    DynIndex = Index - ?HPACK_STATIC_TABLE_SIZE,
    if
        DynIndex >= 1, DynIndex =< length(DynTable) ->
            {Name, Value} = lists:nth(DynIndex, DynTable),
            {ok, Name, Value};
        true ->
            error
    end.

lookup_name(Index, _Ctx) when Index >= 1, Index =< ?HPACK_STATIC_TABLE_SIZE ->
    {Name, _} = lists:nth(Index, ?STATIC_TABLE),
    Name;
lookup_name(Index, #hpack_context{dynamic_table = DynTable}) ->
    DynIndex = Index - ?HPACK_STATIC_TABLE_SIZE,
    if
        DynIndex >= 1, DynIndex =< length(DynTable) ->
            {Name, _} = lists:nth(DynIndex, DynTable),
            Name;
        true ->
            error
    end.

add_to_dynamic_table(Name, Value, Ctx) ->
    EntrySize = entry_size(Name, Value),
    Ctx1 = evict_to_fit(EntrySize, Ctx),
    #hpack_context{
        dynamic_table = DynTable,
        table_size = TableSize,
        max_table_size = MaxSize
    } = Ctx1,
    if
        EntrySize > MaxSize ->
            %% Entry too large, clear table
            Ctx1#hpack_context{dynamic_table = [], table_size = 0};
        true ->
            Ctx1#hpack_context{
                dynamic_table = [{Name, Value}|DynTable],
                table_size = TableSize + EntrySize
            }
    end.

evict_to_fit(NewEntrySize, #hpack_context{
    dynamic_table = DynTable,
    table_size = TableSize,
    max_table_size = MaxSize
} = Ctx) ->
    TargetSize = MaxSize - NewEntrySize,
    if
        TableSize =< TargetSize ->
            Ctx;
        true ->
            evict_entries(DynTable, TableSize, TargetSize, Ctx)
    end.

evict_entries([], _Size, _Target, Ctx) ->
    Ctx#hpack_context{dynamic_table = [], table_size = 0};
evict_entries(DynTable, Size, Target, Ctx) when Size =< Target ->
    Ctx#hpack_context{dynamic_table = DynTable, table_size = Size};
evict_entries(DynTable, Size, Target, Ctx) ->
    case lists:reverse(DynTable) of
        [] ->
            Ctx#hpack_context{dynamic_table = [], table_size = 0};
        [{Name, Value}|Rest] ->
            EntrySize = entry_size(Name, Value),
            evict_entries(lists:reverse(Rest), Size - EntrySize, Target, Ctx)
    end.

entry_size(Name, Value) ->
    byte_size(Name) + byte_size(Value) + 32.

%% Integer encoding (RFC 7541 Section 5.1)

%% @doc Encode an integer with given prefix size.
-spec encode_integer(non_neg_integer(), 1..8) -> binary().
encode_integer(Value, Prefix) ->
    encode_integer(Value, Prefix, 0).

encode_integer(Value, Prefix, Mask) ->
    MaxPrefix = (1 bsl Prefix) - 1,
    if
        Value < MaxPrefix ->
            <<(Mask bsl Prefix bor Value)>>;
        true ->
            encode_integer_continue(Value - MaxPrefix, <<(Mask bsl Prefix bor MaxPrefix)>>)
    end.

encode_integer_continue(Value, Acc) when Value < 128 ->
    <<Acc/binary, Value>>;
encode_integer_continue(Value, Acc) ->
    encode_integer_continue(Value bsr 7, <<Acc/binary, (128 bor (Value band 127))>>).

%% @doc Decode an integer with given prefix size.
-spec decode_integer(binary(), 1..8) -> {ok, non_neg_integer(), binary()} | {error, term()}.
decode_integer(<<>>, _Prefix) ->
    {error, incomplete};
decode_integer(Bin, Prefix) ->
    MaxPrefix = (1 bsl Prefix) - 1,
    Skip = 8 - Prefix,
    <<_:Skip, Value:Prefix, Rest/binary>> = Bin,
    if
        Value < MaxPrefix ->
            {ok, Value, Rest};
        true ->
            decode_integer_continue(Rest, MaxPrefix, 0)
    end.

decode_integer_continue(<<>>, _Value, _Shift) ->
    {error, incomplete};
decode_integer_continue(<<0:1, B:7, Rest/binary>>, Value, Shift) ->
    {ok, Value + (B bsl Shift), Rest};
decode_integer_continue(<<1:1, B:7, Rest/binary>>, Value, Shift) when Shift < 56 ->
    decode_integer_continue(Rest, Value + (B bsl Shift), Shift + 7);
decode_integer_continue(_, _, _) ->
    {error, integer_overflow}.

%% Huffman coding (RFC 7541 Section 5.2)

%% @doc Huffman encode a binary string.
-spec huffman_encode(binary()) -> binary().
huffman_encode(Bin) ->
    Bits = huffman_encode_bits(Bin, <<>>),
    %% Pad with EOS prefix (all 1s)
    PadLen = (8 - (bit_size(Bits) rem 8)) rem 8,
    Padding = (1 bsl PadLen) - 1,
    <<Bits/bits, Padding:PadLen>>.

huffman_encode_bits(<<>>, Acc) ->
    Acc;
huffman_encode_bits(<<C, Rest/binary>>, Acc) ->
    {_, Code, Len} = lists:nth(C + 1, ?HUFFMAN_ENCODE_TABLE),
    huffman_encode_bits(Rest, <<Acc/bits, Code:Len>>).

%% @doc Huffman decode a binary string.
-spec huffman_decode(binary()) -> {ok, binary()} | {error, term()}.
huffman_decode(Bin) ->
    %% Build decode table sorted by code length for efficient matching
    DecodeTable = build_decode_table(),
    huffman_decode_loop(Bin, <<>>, <<>>, DecodeTable).

huffman_decode_loop(<<>>, <<>>, Acc, _Table) ->
    {ok, Acc};
huffman_decode_loop(<<>>, Remaining, Acc, _Table) ->
    %% Check if remaining bits are valid EOS padding (all 1s)
    Len = bit_size(Remaining),
    if
        Len < 8 ->
            Expected = (1 bsl Len) - 1,
            <<Val:Len>> = Remaining,
            if
                Val == Expected -> {ok, Acc};
                true -> {error, invalid_padding}
            end;
        true ->
            {error, incomplete_code}
    end;
huffman_decode_loop(<<B, Rest/binary>>, Bits, Acc, Table) ->
    AllBits = <<Bits/bits, B>>,
    decode_symbols(AllBits, Rest, Acc, Table).

%% Decode as many symbols as possible from the bit buffer
decode_symbols(Bits, MoreBytes, Acc, Table) ->
    case match_huffman_code(Bits, Table) of
        {ok, Char, Remaining} ->
            decode_symbols(Remaining, MoreBytes, <<Acc/binary, Char>>, Table);
        need_more when MoreBytes =:= <<>> ->
            huffman_decode_loop(<<>>, Bits, Acc, Table);
        need_more ->
            huffman_decode_loop(MoreBytes, Bits, Acc, Table);
        {error, _} = Err ->
            Err
    end.

%% Build decode table sorted by code length
build_decode_table() ->
    lists:sort(fun({_, _, L1}, {_, _, L2}) -> L1 =< L2 end, ?HUFFMAN_ENCODE_TABLE).

%% Match a Huffman code from the bit buffer
match_huffman_code(Bits, Table) ->
    match_huffman_code(Bits, Table, bit_size(Bits)).

match_huffman_code(_Bits, [], _BitSize) ->
    need_more;
match_huffman_code(Bits, [{Sym, Code, Len}|Rest], BitSize) when Len =< BitSize ->
    <<Test:Len, Remaining/bits>> = Bits,
    if
        Test == Code, Sym =< 255 ->
            {ok, Sym, Remaining};
        Test == Code, Sym == 256 ->
            {error, eos_in_string};
        true ->
            match_huffman_code(Bits, Rest, BitSize)
    end;
match_huffman_code(_Bits, [{_, _, Len}|_], BitSize) when Len > BitSize ->
    %% All remaining codes are longer than available bits
    need_more.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

new_context_test() ->
    Ctx = new_context(),
    ?assertEqual(?DEFAULT_HEADER_TABLE_SIZE, get_max_table_size(Ctx)).

integer_encode_decode_test_() ->
    [
        %% Examples from RFC 7541 Section C.1
        ?_assertEqual({ok, 10, <<>>}, decode_integer(encode_integer(10, 5), 5)),
        ?_assertEqual({ok, 1337, <<>>}, decode_integer(encode_integer(1337, 5), 5)),
        ?_assertEqual({ok, 42, <<>>}, decode_integer(encode_integer(42, 8), 8))
    ].

integer_roundtrip_test_() ->
    Values = [0, 1, 30, 31, 32, 127, 128, 255, 256, 1337, 16383, 16384, 100000],
    Prefixes = [1, 4, 5, 6, 7, 8],
    [?_assertEqual({ok, V, <<>>}, decode_integer(encode_integer(V, P), P))
     || V <- Values, P <- Prefixes].

huffman_encode_test() ->
    %% Test encoding "www.example.com" from RFC 7541 C.4.1
    Input = <<"www.example.com">>,
    Encoded = huffman_encode(Input),
    ?assertEqual({ok, Input}, huffman_decode(Encoded)).

huffman_roundtrip_test_() ->
    Strings = [
        <<>>,
        <<"a">>,
        <<"test">>,
        <<"Hello, World!">>,
        <<"www.example.com">>,
        <<"no-cache">>,
        <<"custom-key">>,
        <<"custom-value">>
    ],
    [?_assertEqual({ok, S}, huffman_decode(huffman_encode(S))) || S <- Strings].

encode_decode_test() ->
    Ctx = new_context(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"www.example.com">>}
    ],
    {Encoded, Ctx1} = encode(Headers, Ctx),
    {ok, Decoded, _Ctx2} = decode(Encoded, Ctx1),
    ?assertEqual(Headers, Decoded).

static_table_indexed_test() ->
    %% :method GET is index 2
    Ctx = new_context(),
    Headers = [{<<":method">>, <<"GET">>}],
    {Encoded, _} = encode(Headers, Ctx),
    %% Should be a single byte: 0x82 (indexed, index 2)
    ?assertEqual(<<16#82>>, Encoded).

dynamic_table_test() ->
    Ctx = new_context(),
    Headers1 = [{<<"custom-key">>, <<"custom-value">>}],
    {Encoded1, Ctx1} = encode(Headers1, Ctx),
    %% Decode to update receiver's dynamic table
    {ok, _, Ctx2} = decode(Encoded1, Ctx1),
    %% Second time should use indexed
    {Encoded2, _} = encode(Headers1, Ctx2),
    %% Should be shorter (indexed reference)
    ?assert(byte_size(Encoded2) < byte_size(Encoded1)).

-endif.
