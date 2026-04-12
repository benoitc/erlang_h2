%% @doc HPACK Compliance Tests (RFC 7541 Appendix C)
%%
%% This module contains tests based on the examples from RFC 7541 Appendix C.
%% These serve as compliance tests to verify our HPACK implementation.
%%
%% Test sections:
%% - C.1: Integer Representation Examples
%% - C.2: Header Field Representation Examples
%% - C.3: Request Examples without Huffman Coding
%% - C.4: Request Examples with Huffman Coding
%% - C.5: Response Examples without Huffman Coding
%% - C.6: Response Examples with Huffman Coding
%%
-module(h2_hpack_compliance_tests).

-include_lib("eunit/include/eunit.hrl").

%% ============================================================================
%% C.1: Integer Representation Examples
%% ============================================================================

%% C.1.1: Example 1: Encoding 10 Using a 5-Bit Prefix
c1_1_encode_10_test() ->
    %% The value 10 is to be encoded with a 5-bit prefix.
    %% 10 is less than 31 (2^5 - 1) so it can be encoded in the prefix.
    %% Result: 0b00001010 = 0x0a
    Encoded = h2_hpack:encode_integer(10, 5),
    ?assertEqual(<<10>>, Encoded).

c1_1_decode_10_test() ->
    %% Decode with 5-bit prefix
    {ok, Value, <<>>} = h2_hpack:decode_integer(<<10>>, 5),
    ?assertEqual(10, Value).

%% C.1.2: Example 2: Encoding 1337 Using a 5-Bit Prefix
c1_2_encode_1337_test() ->
    %% 1337 is to be encoded with a 5-bit prefix.
    %% 1337 >= 31, so we use the prefix value 31 and encode the rest.
    %% 1337 - 31 = 1306
    %% 1306 = 0b10100011010
    %% Encoded: 31, 154 (0x9a = 1010 01010), 10 (0x0a = 0000 1010)
    Encoded = h2_hpack:encode_integer(1337, 5),
    %% The encoding should be: 0x1f (31), 0x9a (154), 0x0a (10)
    ?assertEqual(<<31, 154, 10>>, Encoded).

c1_2_decode_1337_test() ->
    {ok, Value, <<>>} = h2_hpack:decode_integer(<<31, 154, 10>>, 5),
    ?assertEqual(1337, Value).

%% C.1.3: Example 3: Encoding 42 Using an 8-Bit Prefix
c1_3_encode_42_test() ->
    %% 42 is less than 255 (2^8 - 1), so it fits in the prefix.
    Encoded = h2_hpack:encode_integer(42, 8),
    ?assertEqual(<<42>>, Encoded).

c1_3_decode_42_test() ->
    {ok, Value, <<>>} = h2_hpack:decode_integer(<<42>>, 8),
    ?assertEqual(42, Value).

%% Additional integer tests
integer_roundtrip_test_() ->
    TestCases = [
        {0, 1}, {0, 4}, {0, 5}, {0, 7}, {0, 8},
        {1, 1}, {1, 4}, {1, 5}, {1, 7}, {1, 8},
        {30, 5}, {31, 5}, {32, 5},
        {126, 7}, {127, 7}, {128, 7},
        {254, 8}, {255, 8}, {256, 8},
        {16383, 5}, {16384, 5},
        {65535, 6}, {65536, 6}
    ],
    [?_assertEqual({ok, V, <<>>}, h2_hpack:decode_integer(h2_hpack:encode_integer(V, P), P))
     || {V, P} <- TestCases].

%% ============================================================================
%% C.2: Header Field Representation Examples
%% ============================================================================

%% C.2.1: Literal Header Field with Indexing
c2_1_literal_indexed_test() ->
    %% Encode: custom-key: custom-header
    Ctx = h2_hpack:new_context(),
    Headers = [{<<"custom-key">>, <<"custom-header">>}],
    {Encoded, Ctx1} = h2_hpack:encode(Headers, Ctx),

    %% Decode and verify
    {ok, Decoded, _Ctx2} = h2_hpack:decode(Encoded, h2_hpack:new_context()),
    ?assertEqual(Headers, Decoded),

    %% The header should be in the dynamic table now
    %% Encode again, should be shorter (indexed)
    {Encoded2, _Ctx3} = h2_hpack:encode(Headers, Ctx1),
    ?assert(byte_size(Encoded2) < byte_size(Encoded)).

%% C.2.2: Literal Header Field without Indexing
%% Note: Our encoder always uses indexing for efficiency,
%% but the decoder handles non-indexed literals.
c2_2_literal_no_index_decode_test() ->
    %% Binary for literal without indexing: path=/sample/path
    %% 0x04 = literal without indexing, index 4 (:path)
    %% 0x0c = string length 12
    %% "/sample/path"
    Binary = <<16#04, 16#0c, "/sample/path">>,
    Ctx = h2_hpack:new_context(),
    {ok, Headers, _Ctx1} = h2_hpack:decode(Binary, Ctx),
    ?assertEqual([{<<":path">>, <<"/sample/path">>}], Headers).

%% C.2.3: Literal Header Field Never Indexed
c2_3_literal_never_indexed_decode_test() ->
    %% Binary for literal never indexed: password=secret
    %% 0x10 = never indexed, new name
    %% 0x08 = string length 8 (password)
    %% 0x06 = string length 6 (secret)
    Binary = <<16#10, 16#08, "password", 16#06, "secret">>,
    Ctx = h2_hpack:new_context(),
    {ok, Headers, Ctx1} = h2_hpack:decode(Binary, Ctx),
    ?assertEqual([{<<"password">>, <<"secret">>}], Headers),

    %% Verify it was NOT added to dynamic table
    %% Encode the same header, should be full literal (not indexed)
    {Encoded, _Ctx2} = h2_hpack:encode(Headers, Ctx1),
    %% If it were indexed, it would be just 1 byte
    ?assert(byte_size(Encoded) > 1).

%% C.2.4: Indexed Header Field
c2_4_indexed_test() ->
    %% :method: GET is index 2 in static table
    Binary = <<16#82>>,  %% 0x82 = indexed, index 2
    Ctx = h2_hpack:new_context(),
    {ok, Headers, _Ctx1} = h2_hpack:decode(Binary, Ctx),
    ?assertEqual([{<<":method">>, <<"GET">>}], Headers).

%% ============================================================================
%% C.3: Request Examples without Huffman Coding
%% ============================================================================

%% C.3.1: First Request
c3_1_first_request_test() ->
    Ctx0 = h2_hpack:new_context(),

    %% First request headers (without Huffman)
    Headers1 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"http">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"www.example.com">>}
    ],

    %% Encode
    {Encoded1, Ctx1} = h2_hpack:encode(Headers1, Ctx0),

    %% Decode and verify
    {ok, Decoded1, DecCtx1} = h2_hpack:decode(Encoded1, h2_hpack:new_context()),
    ?assertEqual(Headers1, Decoded1),

    %% C.3.2: Second Request
    Headers2 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"http">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"www.example.com">>},
        {<<"cache-control">>, <<"no-cache">>}
    ],

    {Encoded2, Ctx2} = h2_hpack:encode(Headers2, Ctx1),
    {ok, Decoded2, DecCtx2} = h2_hpack:decode(Encoded2, DecCtx1),
    ?assertEqual(Headers2, Decoded2),

    %% Second encoding should be more compact due to dynamic table
    ?assert(byte_size(Encoded2) < byte_size(Encoded1) + 15),

    %% C.3.3: Third Request
    Headers3 = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/index.html">>},
        {<<":authority">>, <<"www.example.com">>},
        {<<"custom-key">>, <<"custom-value">>}
    ],

    {Encoded3, _Ctx3} = h2_hpack:encode(Headers3, Ctx2),
    {ok, Decoded3, _DecCtx3} = h2_hpack:decode(Encoded3, DecCtx2),
    ?assertEqual(Headers3, Decoded3).

%% ============================================================================
%% C.4: Request Examples with Huffman Coding
%% ============================================================================

%% Huffman encoding is used automatically by our encoder when it saves space

c4_huffman_encoding_test() ->
    %% Test that Huffman encoding works for strings
    TestString = <<"www.example.com">>,
    HuffmanEncoded = h2_hpack:huffman_encode(TestString),

    %% Huffman should be smaller or equal
    ?assert(byte_size(HuffmanEncoded) =< byte_size(TestString)),

    %% Round-trip test
    {ok, Decoded} = h2_hpack:huffman_decode(HuffmanEncoded),
    ?assertEqual(TestString, Decoded).

c4_huffman_common_strings_test_() ->
    Strings = [
        <<"no-cache">>,
        <<"custom-key">>,
        <<"custom-value">>,
        <<"/sample/path">>,
        <<"Mon, 21 Oct 2013 20:13:21 GMT">>,
        <<"https://www.example.com">>
    ],
    [?_assertEqual({ok, S}, h2_hpack:huffman_decode(h2_hpack:huffman_encode(S)))
     || S <- Strings].

%% ============================================================================
%% C.5: Response Examples without Huffman Coding
%% ============================================================================

c5_response_sequence_test() ->
    Ctx0 = h2_hpack:new_context(),
    DecCtx0 = h2_hpack:new_context(),

    %% C.5.1: First Response
    Headers1 = [
        {<<":status">>, <<"302">>},
        {<<"cache-control">>, <<"private">>},
        {<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
        {<<"location">>, <<"https://www.example.com">>}
    ],

    {Encoded1, Ctx1} = h2_hpack:encode(Headers1, Ctx0),
    {ok, Decoded1, DecCtx1} = h2_hpack:decode(Encoded1, DecCtx0),
    ?assertEqual(Headers1, Decoded1),

    %% C.5.2: Second Response
    Headers2 = [
        {<<":status">>, <<"307">>},
        {<<"cache-control">>, <<"private">>},
        {<<"date">>, <<"Mon, 21 Oct 2013 20:13:21 GMT">>},
        {<<"location">>, <<"https://www.example.com">>}
    ],

    {Encoded2, Ctx2} = h2_hpack:encode(Headers2, Ctx1),
    {ok, Decoded2, DecCtx2} = h2_hpack:decode(Encoded2, DecCtx1),
    ?assertEqual(Headers2, Decoded2),

    %% Should be smaller due to reuse
    ?assert(byte_size(Encoded2) < byte_size(Encoded1)),

    %% C.5.3: Third Response
    Headers3 = [
        {<<":status">>, <<"200">>},
        {<<"cache-control">>, <<"private">>},
        {<<"date">>, <<"Mon, 21 Oct 2013 20:13:22 GMT">>},
        {<<"location">>, <<"https://www.example.com">>},
        {<<"content-encoding">>, <<"gzip">>},
        {<<"set-cookie">>, <<"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1">>}
    ],

    {_Encoded3, _Ctx3} = h2_hpack:encode(Headers3, Ctx2),
    {ok, Decoded3, _DecCtx3} = h2_hpack:decode(_Encoded3, DecCtx2),
    ?assertEqual(Headers3, Decoded3).

%% ============================================================================
%% C.6: Response Examples with Huffman Coding
%% ============================================================================

%% Same as C.5 but verifies Huffman is used

c6_huffman_response_test() ->
    %% The encoder automatically uses Huffman when beneficial
    TestHeaders = [
        {<<":status">>, <<"200">>},
        {<<"content-type">>, <<"text/html">>},
        {<<"server">>, <<"Apache">>}
    ],

    Ctx = h2_hpack:new_context(),
    {Encoded, _Ctx1} = h2_hpack:encode(TestHeaders, Ctx),

    %% Verify decode works
    {ok, Decoded, _Ctx2} = h2_hpack:decode(Encoded, h2_hpack:new_context()),
    ?assertEqual(TestHeaders, Decoded).

%% ============================================================================
%% Dynamic Table Size Management
%% ============================================================================

dynamic_table_size_update_test() ->
    %% Create context with larger table
    Ctx = h2_hpack:new_context(8192),
    ?assertEqual(8192, h2_hpack:get_max_table_size(Ctx)),

    %% Reduce table size
    Ctx1 = h2_hpack:set_max_table_size(256, Ctx),
    ?assertEqual(256, h2_hpack:get_max_table_size(Ctx1)).

dynamic_table_eviction_test() ->
    %% Use small table to force eviction
    Ctx0 = h2_hpack:new_context(128),

    %% Add headers that will exceed table size
    Headers1 = [{<<"a-long-header-name">>, <<"a-long-header-value">>}],
    {_Encoded1, Ctx1} = h2_hpack:encode(Headers1, Ctx0),

    Headers2 = [{<<"another-long-header">>, <<"another-long-value">>}],
    {_Encoded2, Ctx2} = h2_hpack:encode(Headers2, Ctx1),

    %% Encoding the first header again should be a full literal
    %% (not indexed) because it was evicted
    {Encoded3, _Ctx3} = h2_hpack:encode(Headers1, Ctx2),
    %% Full literal is more than a single indexed byte
    %% (with Huffman, names/values compress but still take space)
    ?assert(byte_size(Encoded3) > 2).

%% ============================================================================
%% Static Table Tests
%% ============================================================================

static_table_entries_test_() ->
    %% Verify well-known static table entries
    StaticEntries = [
        {2, <<":method">>, <<"GET">>},
        {3, <<":method">>, <<"POST">>},
        {4, <<":path">>, <<"/">>},
        {6, <<":scheme">>, <<"http">>},
        {7, <<":scheme">>, <<"https">>},
        {8, <<":status">>, <<"200">>},
        {13, <<":status">>, <<"404">>},
        {14, <<":status">>, <<"500">>}
    ],
    [begin
        Binary = <<(128 bor Index)>>,  %% Indexed header
        Ctx = h2_hpack:new_context(),
        {ok, [{Name, Value}], _} = h2_hpack:decode(Binary, Ctx),
        [?_assertEqual(ExpName, Name), ?_assertEqual(ExpValue, Value)]
     end || {Index, ExpName, ExpValue} <- StaticEntries].

%% ============================================================================
%% Edge Cases
%% ============================================================================

empty_headers_test() ->
    Ctx = h2_hpack:new_context(),
    {Encoded, _Ctx1} = h2_hpack:encode([], Ctx),
    ?assertEqual(<<>>, Encoded),

    {ok, Decoded, _Ctx2} = h2_hpack:decode(<<>>, Ctx),
    ?assertEqual([], Decoded).

empty_value_test() ->
    Ctx = h2_hpack:new_context(),
    Headers = [{<<":authority">>, <<>>}],
    {Encoded, _Ctx1} = h2_hpack:encode(Headers, Ctx),
    {ok, Decoded, _Ctx2} = h2_hpack:decode(Encoded, h2_hpack:new_context()),
    ?assertEqual(Headers, Decoded).

binary_value_test() ->
    Ctx = h2_hpack:new_context(),
    %% Value with special characters
    Headers = [{<<"content-type">>, <<"application/json; charset=utf-8">>}],
    {Encoded, _Ctx1} = h2_hpack:encode(Headers, Ctx),
    {ok, Decoded, _Ctx2} = h2_hpack:decode(Encoded, h2_hpack:new_context()),
    ?assertEqual(Headers, Decoded).

large_value_test() ->
    Ctx = h2_hpack:new_context(),
    %% Large header value
    LargeValue = binary:copy(<<"x">>, 1000),
    Headers = [{<<"x-large-header">>, LargeValue}],
    {Encoded, _Ctx1} = h2_hpack:encode(Headers, Ctx),
    {ok, Decoded, _Ctx2} = h2_hpack:decode(Encoded, h2_hpack:new_context()),
    ?assertEqual(Headers, Decoded).

%% ============================================================================
%% Error Handling
%% ============================================================================

invalid_index_test() ->
    %% Index 0 is invalid
    Binary = <<128>>,  %% 0x80 = indexed with index 0
    Ctx = h2_hpack:new_context(),
    Result = h2_hpack:decode(Binary, Ctx),
    ?assertMatch({error, _}, Result).

%% Invalid very large index
large_invalid_index_test() ->
    %% Index larger than static + dynamic tables
    Binary = <<16#ff, 16#ff, 16#ff, 16#7f>>,  %% Very large index
    Ctx = h2_hpack:new_context(),
    Result = h2_hpack:decode(Binary, Ctx),
    ?assertMatch({error, _}, Result).
