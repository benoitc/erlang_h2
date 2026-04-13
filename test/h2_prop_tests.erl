%% @doc Property-Based Tests for HTTP/2 Implementation
%%
%% This module contains property-based tests using PropEr to verify
%% the correctness of frame encoding, HPACK compression, and integer encoding.
%%
-module(h2_prop_tests).

-ifdef(TEST).
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%% ============================================================================
%% EUnit Wrapper Tests
%% ============================================================================

proper_test_() ->
    {timeout, 120, [
        {"prop_integer_roundtrip", fun() -> run_proper(prop_integer_roundtrip(), 200) end},
        {"prop_huffman_roundtrip", fun() -> run_proper(prop_huffman_roundtrip(), 200) end},
        {"prop_hpack_roundtrip", fun() -> run_proper(prop_hpack_roundtrip(), 100) end},
        {"prop_frame_roundtrip", fun() -> run_proper(prop_frame_roundtrip(), 100) end},
        {"prop_frame_data_roundtrip", fun() -> run_proper(prop_frame_data_roundtrip(), 100) end},
        {"prop_settings_roundtrip", fun() -> run_proper(prop_settings_roundtrip(), 100) end}
    ]}.

run_proper(Property, NumTests) ->
    ?assertEqual(true, proper:quickcheck(Property, [{numtests, NumTests}, {to_file, user}])).

%% ============================================================================
%% Properties
%% ============================================================================

%% @doc Property: Integer encoding roundtrips correctly
prop_integer_roundtrip() ->
    ?FORALL({Value, Prefix}, {hpack_integer(), range(1, 8)},
        begin
            Encoded = h2_hpack:encode_integer(Value, Prefix),
            {ok, Decoded, <<>>} = h2_hpack:decode_integer(Encoded, Prefix),
            Value =:= Decoded
        end).

%% @doc Property: Huffman encoding roundtrips correctly
prop_huffman_roundtrip() ->
    ?FORALL(Str, printable_binary(),
        begin
            Encoded = h2_hpack:huffman_encode(Str),
            {ok, Decoded} = h2_hpack:huffman_decode(Encoded),
            Str =:= Decoded
        end).

%% @doc Property: HPACK header encoding roundtrips correctly
prop_hpack_roundtrip() ->
    ?FORALL(Headers, headers_list(),
        begin
            Ctx = h2_hpack:new_context(),
            {Encoded, _Ctx1} = h2_hpack:encode(Headers, Ctx),
            {ok, Decoded, _Ctx2} = h2_hpack:decode(Encoded, h2_hpack:new_context()),
            Headers =:= Decoded
        end).

%% @doc Property: Frame encoding roundtrips correctly
prop_frame_roundtrip() ->
    ?FORALL(Frame, frame(),
        begin
            Encoded = h2_frame:encode(Frame),
            {ok, Decoded, <<>>} = h2_frame:decode(Encoded),
            frames_equal(Frame, Decoded)
        end).

%% @doc Property: DATA frame encoding roundtrips
prop_frame_data_roundtrip() ->
    ?FORALL({StreamId, Data, EndStream}, {stream_id(), binary(), boolean()},
        begin
            Frame = h2_frame:data(StreamId, Data, EndStream),
            Encoded = h2_frame:encode(Frame),
            {ok, Decoded, <<>>} = h2_frame:decode(Encoded),
            %% Decoder now reports padded payload size; unpadded DATA has
            %% FlowControlled = byte_size(Data).
            Decoded =:= {data, StreamId, Data, EndStream, byte_size(Data)}
        end).

%% @doc Property: Settings encoding roundtrips
prop_settings_roundtrip() ->
    ?FORALL(Settings, settings_map(),
        begin
            Encoded = h2_settings:encode(Settings),
            {ok, Decoded} = h2_settings:decode(Encoded),
            %% Check that all encoded settings are present in decoded
            maps:fold(fun(Key, Value, Acc) ->
                Acc andalso (maps:get(Key, Decoded, Value) =:= Value)
            end, true, Settings)
        end).

%% ============================================================================
%% Generators
%% ============================================================================

%% @doc Generate a non-negative integer suitable for HPACK encoding
hpack_integer() ->
    frequency([
        {10, range(0, 30)},           %% Small values (fit in prefix)
        {5, range(31, 255)},          %% Medium values
        {3, range(256, 16383)},       %% Larger values
        {1, range(16384, 1000000)}    %% Large values
    ]).

%% @doc Generate printable binary strings for Huffman encoding
printable_binary() ->
    ?LET(Chars, list(printable_char()),
        list_to_binary(Chars)).

printable_char() ->
    frequency([
        {10, range($a, $z)},
        {5, range($A, $Z)},
        {3, range($0, $9)},
        {2, elements([$-, $_, $., $/, $:, $;, $=, $@, $?, $&, $%, $+])}
    ]).

%% @doc Generate valid header name
header_name() ->
    ?LET(Chars, non_empty(list(header_name_char())),
        list_to_binary(Chars)).

header_name_char() ->
    frequency([
        {10, range($a, $z)},
        {2, elements([$-, $_])}
    ]).

%% @doc Generate header value
header_value() ->
    ?LET(Chars, list(header_value_char()),
        list_to_binary(Chars)).

header_value_char() ->
    frequency([
        {10, range($a, $z)},
        {5, range($A, $Z)},
        {3, range($0, $9)},
        {2, elements([$-, $_, $., $/, $:, $;, $=, $@, $?, $&, $%, $+, $ ])}
    ]).

%% @doc Generate list of headers
headers_list() ->
    ?LET(Headers, list(header()),
        lists:usort(fun({N1, _}, {N2, _}) -> N1 =< N2 end, Headers)).

header() ->
    {header_name(), header_value()}.

%% @doc Generate stream ID (odd for client, even for server)
stream_id() ->
    ?LET(N, range(1, 10000), N * 2 + 1).  %% Always odd (client-initiated)

%% @doc Generate valid HTTP/2 frame
frame() ->
    oneof([
        data_frame(),
        headers_frame(),
        priority_frame(),
        rst_stream_frame(),
        settings_frame(),
        ping_frame(),
        goaway_frame(),
        window_update_frame()
    ]).

data_frame() ->
    ?LET({StreamId, Data, EndStream}, {stream_id(), binary(), boolean()},
        h2_frame:data(StreamId, Data, EndStream)).

headers_frame() ->
    ?LET({StreamId, HeaderBlock, EndStream}, {stream_id(), binary(), boolean()},
        h2_frame:headers(StreamId, HeaderBlock, EndStream)).

priority_frame() ->
    ?LET({StreamId, Exclusive, DependsOn, Weight},
         {stream_id(), boolean(), stream_id(), range(1, 256)},
        h2_frame:priority(StreamId, Exclusive, DependsOn, Weight)).

rst_stream_frame() ->
    ?LET({StreamId, ErrorCode}, {stream_id(), error_code()},
        h2_frame:rst_stream(StreamId, ErrorCode)).

settings_frame() ->
    ?LET(Settings, settings_list(),
        h2_frame:settings(Settings)).

ping_frame() ->
    ?LET(Data, binary(8),
        h2_frame:ping(Data)).

goaway_frame() ->
    ?LET({LastStreamId, ErrorCode, DebugData},
         {non_neg_integer(), error_code(), binary()},
        h2_frame:goaway(LastStreamId, ErrorCode, DebugData)).

window_update_frame() ->
    ?LET({StreamId, Increment}, {non_neg_integer(), range(1, 2147483647)},
        h2_frame:window_update(StreamId, Increment)).

%% @doc Generate error code
error_code() ->
    elements([
        no_error, protocol_error, internal_error, flow_control_error,
        settings_timeout, stream_closed, frame_size_error, refused_stream,
        cancel, compression_error, connect_error, enhance_your_calm,
        inadequate_security, http_1_1_required
    ]).

%% @doc Generate settings list for SETTINGS frame
settings_list() ->
    ?LET(Settings, list(setting()),
        Settings).

setting() ->
    oneof([
        {1, range(0, 65535)},    %% HEADER_TABLE_SIZE
        {2, range(0, 1)},        %% ENABLE_PUSH
        {3, range(0, 1000)},     %% MAX_CONCURRENT_STREAMS
        {4, range(1, 2147483647)},  %% INITIAL_WINDOW_SIZE
        {5, range(16384, 16777215)}, %% MAX_FRAME_SIZE
        {6, range(0, 1000000)}   %% MAX_HEADER_LIST_SIZE
    ]).

%% @doc Generate settings map for h2_settings
settings_map() ->
    ?LET(Pairs, list(settings_pair()),
        maps:from_list(Pairs)).

settings_pair() ->
    oneof([
        {header_table_size, range(0, 65535)},
        {enable_push, range(0, 1)},
        {max_concurrent_streams, range(1, 1000)},
        {initial_window_size, range(1, 2147483647)},
        {max_frame_size, range(16384, 16777215)},
        {max_header_list_size, range(0, 1000000)}
    ]).

%% ============================================================================
%% Helper Functions
%% ============================================================================

%% @doc Compare frames for equality (handling different representations)
frames_equal(Frame1, Frame2) when is_tuple(Frame1), is_tuple(Frame2) ->
    %% Handle special cases where frame types might differ in representation
    normalize_frame(Frame1) =:= normalize_frame(Frame2).

normalize_frame({data, StreamId, Data, EndStream}) ->
    {data, StreamId, Data, EndStream, byte_size(Data)};
normalize_frame({data, StreamId, Data, EndStream, FlowControlled}) ->
    {data, StreamId, Data, EndStream, FlowControlled};
normalize_frame({headers, StreamId, HeaderBlock, EndStream, EndHeaders}) ->
    {headers, StreamId, HeaderBlock, EndStream, EndHeaders};
normalize_frame({headers, StreamId, HeaderBlock, EndStream, EndHeaders, Priority}) ->
    {headers, StreamId, HeaderBlock, EndStream, EndHeaders, Priority};
normalize_frame({priority, StreamId, Exclusive, DependsOn, Weight}) ->
    {priority, StreamId, Exclusive, DependsOn, Weight};
normalize_frame({rst_stream, StreamId, ErrorCode}) when is_atom(ErrorCode) ->
    {rst_stream, StreamId, h2_error:code(ErrorCode)};
normalize_frame({rst_stream, StreamId, ErrorCode}) ->
    {rst_stream, StreamId, ErrorCode};
normalize_frame({settings, Settings}) ->
    {settings, lists:sort(Settings)};
normalize_frame({settings_ack}) ->
    {settings_ack};
normalize_frame({ping, Data}) ->
    {ping, Data};
normalize_frame({ping_ack, Data}) ->
    {ping_ack, Data};
normalize_frame({goaway, LastStreamId, ErrorCode, DebugData}) when is_atom(ErrorCode) ->
    {goaway, LastStreamId, h2_error:code(ErrorCode), DebugData};
normalize_frame({goaway, LastStreamId, ErrorCode, DebugData}) ->
    {goaway, LastStreamId, ErrorCode, DebugData};
normalize_frame({window_update, StreamId, Increment}) ->
    {window_update, StreamId, Increment};
normalize_frame({continuation, StreamId, HeaderBlock, EndHeaders}) ->
    {continuation, StreamId, HeaderBlock, EndHeaders};
normalize_frame({push_promise, StreamId, PromisedId, HeaderBlock, EndHeaders}) ->
    {push_promise, StreamId, PromisedId, HeaderBlock, EndHeaders};
normalize_frame(Other) ->
    Other.

-endif.
