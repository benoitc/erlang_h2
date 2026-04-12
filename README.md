# h2

HTTP/2 protocol library for Erlang implementing:

- **RFC 7540** - HTTP/2 Protocol
- **RFC 7541** - HPACK Header Compression
- **RFC 9297** - Capsule Protocol (WebTransport tunneling)
- **RFC 8441** - Extended CONNECT for WebSockets/WebTransport

## Features

- Complete HTTP/2 frame encoding/decoding
- HPACK header compression with dynamic table and Huffman encoding
- Capsule protocol support for HTTP CONNECT tunnels
- QUIC-style variable-length integer encoding
- Settings management with validation
- Error code definitions

## Installation

Add to your `rebar.config`:

```erlang
{deps, [
    {h2, "0.1.0", {git, "https://github.com/benoitc/h2.git", {tag, "0.1.0"}}}
]}.
```

## Usage

### Frame Encoding/Decoding

```erlang
%% Create a HEADERS frame
HeadersFrame = h2_frame:headers(1, true, true, HeaderBlock),
Binary = h2_frame:encode(HeadersFrame),

%% Decode frames from binary
{ok, Frame, Rest} = h2_frame:decode(Binary),
%% Or handle incomplete data
{more, BytesNeeded} = h2_frame:decode(PartialBinary).
```

### HPACK Header Compression

```erlang
%% Create encoder/decoder contexts
EncCtx = h2_hpack:new_context(),
DecCtx = h2_hpack:new_context(),

%% Encode headers
Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
{ok, Encoded, EncCtx2} = h2_hpack:encode(Headers, EncCtx),

%% Decode headers
{ok, Headers, DecCtx2} = h2_hpack:decode(Encoded, DecCtx).
```

### Settings

```erlang
%% Get default settings
Settings = h2_settings:default(),

%% Modify settings
Settings2 = h2_settings:set(max_concurrent_streams, 100, Settings),

%% Encode for SETTINGS frame
Payload = h2_settings:encode(Settings2).
```

### Capsule Protocol

```erlang
%% Create a DATAGRAM capsule
Capsule = h2_capsule:datagram(Payload),
Binary = h2_capsule:encode(datagram, Payload),

%% Decode capsules
{ok, {Type, Payload}, Rest} = h2_capsule:decode(Binary).
```

## Modules

| Module | Description |
|--------|-------------|
| h2_frame | HTTP/2 frame encoding/decoding |
| h2_hpack | HPACK header compression |
| h2_settings | Settings parameter management |
| h2_error | Error code definitions |
| h2_capsule | Capsule protocol (RFC 9297) |
| h2_varint | QUIC variable-length integers |

## Building

```bash
rebar3 compile
```

## Testing

```bash
rebar3 eunit
```

## Documentation

See [doc/features.md](doc/features.md) for detailed documentation.

## License

Apache License 2.0
