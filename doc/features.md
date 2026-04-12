# h2 Features

## Overview

h2 provides low-level HTTP/2 protocol primitives for Erlang applications. It handles frame encoding/decoding, header compression, and related protocol details without imposing connection management strategies.

## Modules

### h2_frame - Frame Encoding/Decoding

Implements all HTTP/2 frame types per RFC 7540 Section 4.

#### Frame Types

| Type | Code | Description |
|------|------|-------------|
| DATA | 0x0 | Conveys payload data |
| HEADERS | 0x1 | Opens a stream, carries headers |
| PRIORITY | 0x2 | Stream dependency and weight |
| RST_STREAM | 0x3 | Terminates a stream |
| SETTINGS | 0x4 | Configuration parameters |
| PUSH_PROMISE | 0x5 | Server push initiation |
| PING | 0x6 | Connection health check |
| GOAWAY | 0x7 | Connection shutdown |
| WINDOW_UPDATE | 0x8 | Flow control increment |
| CONTINUATION | 0x9 | Continuation of header block |

#### API

```erlang
%% Encoding
h2_frame:encode(Frame) -> binary().

%% Decoding (streaming-aware)
h2_frame:decode(Binary) -> {ok, Frame, Rest} | {more, BytesNeeded} | {error, Reason}.

%% Frame constructors
h2_frame:data(StreamId, EndStream, Data) -> frame().
h2_frame:data(StreamId, EndStream, Data, PadLength) -> frame().
h2_frame:headers(StreamId, EndStream, EndHeaders, HeaderBlock) -> frame().
h2_frame:headers(StreamId, EndStream, EndHeaders, HeaderBlock, PadLength) -> frame().
h2_frame:priority(StreamId, Exclusive, DepStreamId, Weight) -> frame().
h2_frame:rst_stream(StreamId, ErrorCode) -> frame().
h2_frame:settings(SettingsList) -> frame().
h2_frame:settings_ack() -> frame().
h2_frame:push_promise(StreamId, PromisedId, EndHeaders, HeaderBlock) -> frame().
h2_frame:ping(OpaqueData) -> frame().
h2_frame:ping_ack(OpaqueData) -> frame().
h2_frame:goaway(LastStreamId, ErrorCode, DebugData) -> frame().
h2_frame:window_update(StreamId, Increment) -> frame().
h2_frame:continuation(StreamId, EndHeaders, HeaderBlock) -> frame().
```

#### Streaming Decode

The decoder handles incomplete data gracefully:

```erlang
case h2_frame:decode(Buffer) of
    {ok, Frame, Rest} ->
        %% Process frame, continue with Rest
        handle_frame(Frame),
        decode_loop(Rest);
    {more, N} ->
        %% Need N more bytes, wait for more data
        receive_more(N, Buffer);
    {error, Reason} ->
        %% Protocol error
        handle_error(Reason)
end.
```

### h2_hpack - Header Compression

HPACK implementation per RFC 7541 with static table, dynamic table, and Huffman encoding.

#### Features

- **Static Table**: 61 predefined common headers (RFC 7541 Appendix A)
- **Dynamic Table**: FIFO eviction with configurable max size
- **Huffman Encoding**: Optional string compression
- **Integer Encoding**: Variable-length prefix encoding (1-8 bit prefixes)

#### API

```erlang
%% Context management
h2_hpack:new_context() -> context().
h2_hpack:new_context(MaxTableSize) -> context().
h2_hpack:set_max_table_size(NewSize, Context) -> context().

%% Encoding/Decoding
h2_hpack:encode(Headers, Context) -> {ok, Binary, NewContext}.
h2_hpack:decode(Binary, Context) -> {ok, Headers, NewContext} | {error, Reason}.

%% Huffman
h2_hpack:huffman_encode(Binary) -> Binary.
h2_hpack:huffman_decode(Binary) -> {ok, Binary} | {error, Reason}.

%% Integer encoding
h2_hpack:encode_integer(Value, PrefixBits) -> Binary.
h2_hpack:decode_integer(Binary, PrefixBits) -> {ok, Value, Rest}.
```

#### Header Encoding Strategies

1. **Indexed**: Exact match in static/dynamic table (most efficient)
2. **Literal with Indexing**: Adds to dynamic table for future reference
3. **Literal without Indexing**: Temporary headers, not cached

### h2_settings - Settings Management

HTTP/2 settings parameters per RFC 7540 Section 6.5.

#### Parameters

| Setting | Default | Description |
|---------|---------|-------------|
| header_table_size | 4096 | HPACK dynamic table size |
| enable_push | 1 | Server push enabled |
| max_concurrent_streams | unlimited | Maximum concurrent streams |
| initial_window_size | 65535 | Initial flow control window |
| max_frame_size | 16384 | Maximum frame payload size |
| max_header_list_size | unlimited | Maximum header list size |
| enable_connect_protocol | 0 | Extended CONNECT (RFC 8441) |

#### API

```erlang
h2_settings:default() -> settings().
h2_settings:get(Key, Settings) -> Value | undefined.
h2_settings:set(Key, Value, Settings) -> settings().
h2_settings:merge(Received, Current) -> settings().
h2_settings:encode(Settings) -> binary().
h2_settings:decode(Binary) -> {ok, Settings} | {error, Reason}.
h2_settings:validate(Settings) -> ok | {error, Reason}.
```

### h2_error - Error Codes

HTTP/2 error codes per RFC 7540 Section 7.

#### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x0 | NO_ERROR | Graceful shutdown |
| 0x1 | PROTOCOL_ERROR | Protocol violation |
| 0x2 | INTERNAL_ERROR | Implementation fault |
| 0x3 | FLOW_CONTROL_ERROR | Flow control violation |
| 0x4 | SETTINGS_TIMEOUT | Settings not acknowledged |
| 0x5 | STREAM_CLOSED | Frame on closed stream |
| 0x6 | FRAME_SIZE_ERROR | Invalid frame size |
| 0x7 | REFUSED_STREAM | Stream refused |
| 0x8 | CANCEL | Stream cancelled |
| 0x9 | COMPRESSION_ERROR | HPACK decompression failure |
| 0xa | CONNECT_ERROR | TCP connection error |
| 0xb | ENHANCE_YOUR_CALM | Excessive load |
| 0xc | INADEQUATE_SECURITY | TLS requirements not met |
| 0xd | HTTP_1_1_REQUIRED | Use HTTP/1.1 instead |

#### API

```erlang
h2_error:code(Name) -> integer().
h2_error:name(Code) -> atom().
h2_error:format(CodeOrName) -> string().
```

### h2_capsule - Capsule Protocol

RFC 9297 Capsule Protocol for HTTP CONNECT tunnels and WebTransport.

#### Format

```
Capsule {
  Type (variable-length integer),
  Length (variable-length integer),
  Payload (..)
}
```

#### API

```erlang
h2_capsule:encode(Type, Payload) -> binary().
h2_capsule:decode(Binary) -> {ok, {Type, Payload}, Rest} | {more, N} | {error, Reason}.
h2_capsule:decode_all(Binary) -> {ok, Capsules, Rest} | {error, Reason}.
h2_capsule:datagram(Payload) -> capsule().
```

### h2_varint - Variable-Length Integers

QUIC-style variable-length integer encoding per RFC 9000 Section 16.

#### Encoding Table

| 2 MSBs | Length | Range |
|--------|--------|-------|
| 00 | 1 byte | 0-63 |
| 01 | 2 bytes | 0-16,383 |
| 10 | 4 bytes | 0-1,073,741,823 |
| 11 | 8 bytes | 0-4,611,686,018,427,387,903 |

#### API

```erlang
h2_varint:encode(Integer) -> binary().
h2_varint:decode(Binary) -> {ok, Integer, Rest} | {more, N} | {error, Reason}.
h2_varint:encoded_size(Integer) -> 1 | 2 | 4 | 8.
```

## Protocol Constants

Available in `include/h2.hrl`:

```erlang
%% Connection preface (24 bytes)
-define(H2_PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).

%% Frame size limits
-define(H2_DEFAULT_MAX_FRAME_SIZE, 16384).
-define(H2_MAX_MAX_FRAME_SIZE, 16777215).

%% Window size limits
-define(H2_MAX_WINDOW_SIZE, 2147483647).
```

## Example: Simple HTTP/2 Client

```erlang
-module(h2_example).
-export([request/3]).

request(Host, Port, Path) ->
    {ok, Sock} = gen_tcp:connect(Host, Port, [binary, {active, false}]),

    %% Send connection preface
    ok = gen_tcp:send(Sock, ?H2_PREFACE),

    %% Send SETTINGS
    Settings = h2_frame:settings([]),
    ok = gen_tcp:send(Sock, h2_frame:encode(Settings)),

    %% Create request headers
    EncCtx = h2_hpack:new_context(),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"http">>},
        {<<":authority">>, list_to_binary(Host)},
        {<<":path">>, Path}
    ],
    {ok, HeaderBlock, _} = h2_hpack:encode(Headers, EncCtx),

    %% Send HEADERS frame
    HeadersFrame = h2_frame:headers(1, true, true, HeaderBlock),
    ok = gen_tcp:send(Sock, h2_frame:encode(HeadersFrame)),

    %% Receive response...
    receive_response(Sock).
```

## Testing

Run all tests:

```bash
rebar3 eunit
```

Run tests with coverage:

```bash
rebar3 cover
```
