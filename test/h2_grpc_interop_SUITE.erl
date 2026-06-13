%% @doc gRPC interop: drive an h2-hosted gRPC echo service from a real gRPC
%% client (grpcurl) to surface bidi divergences only a third-party stack sees -
%% trailer encoding, `te: trailers', half-close, content-type, flow control.
%%
%% The echo service is protobuf-agnostic: request and response message types are
%% identical, so the handler mirrors the inbound DATA byte stream verbatim (which
%% is a valid stream of the same length-prefixed messages) and ends with a
%% `grpc-status: 0' trailer. grpcurl does the protobuf encode/decode.
%%
%% Install grpcurl (macOS): `brew install grpcurl`
%% Install grpcurl (Linux): download the release binary from
%%   https://github.com/fullstorydev/grpcurl/releases.
-module(h2_grpc_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-export([bidi_stream_echo_test/1, unary_echo_test/1]).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [bidi_stream_echo_test, unary_echo_test].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(h2),
    case os:find_executable("grpcurl") of
        false -> {skip, "grpcurl not installed"};
        _     -> Config
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    process_flag(trap_exit, true),
    Handler = fun(Conn, StreamId, _Method, _Path, _Headers) ->
        grpc_echo(Conn, StreamId)
    end,
    {ok, ServerRef} = h2:start_server(0, #{handler => Handler, transport => tcp}),
    Port = h2:server_port(ServerRef),
    Proto = write_proto(?config(priv_dir, Config)),
    [{server_ref, ServerRef}, {port, Port}, {proto, Proto} | Config].

end_per_testcase(_TestCase, Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        Ref       -> h2:stop_server(Ref)
    end,
    timer:sleep(50),
    ok.

%% ============================================================================
%% Tests
%% ============================================================================

%% Client-streaming + server-streaming over one stream: grpcurl sends two
%% messages, half-closes, and must read both echoed back plus an OK status.
bidi_stream_echo_test(Config) ->
    %% bytes payloads are base64 in protobuf JSON: aGVsbG8= = "hello",
    %% d29ybGQ= = "world".
    Input = "{\"payload\":\"aGVsbG8=\"}\n{\"payload\":\"d29ybGQ=\"}\n",
    Output = run_grpcurl(Config, "echo.Echo/BidiStream", Input),
    ?assert(contains(Output, "aGVsbG8=")),
    ?assert(contains(Output, "d29ybGQ=")),
    assert_ok_exit(Output).

%% Single request/response over the same echo path.
unary_echo_test(Config) ->
    Input = "{\"payload\":\"cGluZw==\"}\n",   %% cGluZw== = "ping"
    Output = run_grpcurl(Config, "echo.Echo/BidiStream", Input),
    ?assert(contains(Output, "cGluZw==")),
    assert_ok_exit(Output).

%% ============================================================================
%% gRPC echo handler (protobuf-agnostic byte mirror)
%% ============================================================================

grpc_echo(Conn, Sid) ->
    ok = h2:set_stream_handler(Conn, Sid, self()),
    ok = h2:send_response(Conn, Sid, 200,
                          [{<<"content-type">>, <<"application/grpc">>}]),
    echo_loop(Conn, Sid).

echo_loop(Conn, Sid) ->
    receive
        {h2, Conn, {data, Sid, <<>>, true}} ->
            send_ok_trailer(Conn, Sid);
        {h2, Conn, {data, Sid, Bytes, true}} ->
            ok = h2:send_data(Conn, Sid, Bytes, false),
            send_ok_trailer(Conn, Sid);
        {h2, Conn, {data, Sid, Bytes, false}} ->
            ok = h2:send_data(Conn, Sid, Bytes, false),
            echo_loop(Conn, Sid);
        {h2, Conn, _Other} ->
            echo_loop(Conn, Sid)
    after 10000 ->
        ok
    end.

send_ok_trailer(Conn, Sid) ->
    ok = h2:send_trailers(Conn, Sid, [{<<"grpc-status">>, <<"0">>}]).

%% ============================================================================
%% Helpers
%% ============================================================================

write_proto(Dir) ->
    Path = filename:join(Dir, "echo.proto"),
    Proto =
        "syntax = \"proto3\";\n"
        "package echo;\n"
        "message Msg { bytes payload = 1; }\n"
        "service Echo {\n"
        "  rpc BidiStream(stream Msg) returns (stream Msg);\n"
        "}\n",
    ok = file:write_file(Path, Proto),
    Path.

run_grpcurl(Config, Method, Input) ->
    Port  = ?config(port, Config),
    Proto = ?config(proto, Config),
    Dir   = filename:dirname(Proto),
    Base  = filename:basename(Proto),
    Cmd = io_lib:format(
        "printf '%s' '~s' | grpcurl -plaintext -import-path ~s -proto ~s -d @ "
        "127.0.0.1:~p ~s ; echo __EXIT__=$?",
        [Input, Dir, Base, Port, Method]),
    Flat = lists:flatten(Cmd),
    ct:pal("grpcurl command: ~s", [Flat]),
    Output = os:cmd(Flat),
    ct:pal("~ts", [unicode:characters_to_binary(Output)]),
    Output.

assert_ok_exit(Output) ->
    case re:run(Output, "__EXIT__=(\\d+)", [{capture, [1], list}]) of
        {match, ["0"]} -> ok;
        Other          -> ct:fail({grpcurl_failed, Other, Output})
    end.

contains(Haystack, Needle) ->
    string:find(Haystack, Needle) =/= nomatch.
