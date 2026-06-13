%% @doc gRPC client interop: drive a real gRPC server (grpc-python) with our h2
%% CLIENT over a bidi stream. The complementary direction to
%% h2_grpc_interop_SUITE - most likely to surface client-side flow-control and
%% half-close bugs against a battle-tested server.
%%
%% The server is protobuf-free: grpcio's generic-handler API with identity
%% (bytes) serializers echoes raw message bytes, so no protoc / generated stubs
%% are needed. Our client supplies the gRPC framing (5-byte length prefix) and
%% the HTTP/2 request shape; grpcio handles its half, including grpc-status
%% trailers.
%%
%% Requires python3 with grpcio. Point GRPC_PYTHON at a suitable interpreter
%% (e.g. a venv) or have `python3 -c "import grpc"` succeed on PATH; the suite
%% skips when neither is available.
-module(h2_grpc_client_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-export([bidi_echo_test/1, large_message_flow_control_test/1]).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [bidi_echo_test, large_message_flow_control_test].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(h2),
    case find_python() of
        {ok, Python} -> [{python, Python} | Config];
        error        -> {skip, "python3 with grpcio not available"}
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    process_flag(trap_exit, true),
    Python = ?config(python, Config),
    Script = write_server_script(?config(priv_dir, Config)),
    Server = start_grpc_server(Python, Script),
    [{server, Server} | Config].

end_per_testcase(_TestCase, Config) ->
    case ?config(server, Config) of
        undefined -> ok;
        Server    -> stop_grpc_server(Server)
    end,
    ok.

%% ============================================================================
%% Tests
%% ============================================================================

%% Five messages out, half-close, five echoed back plus an OK status - exercises
%% our client's request shape, repeated send_data, END_STREAM half-close, and
%% reading server DATA + trailers.
bidi_echo_test(Config) ->
    Port = server_port(?config(server, Config)),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = open_grpc_stream(Client, Port),
    Payloads = [<<"msg-", (integer_to_binary(I))/binary>> || I <- lists:seq(1, 5)],
    {Echoed, Trailers} = grpc_bidi(Client, Sid, Payloads, 15000),
    ?assertEqual(Payloads, Echoed),
    ?assertEqual(<<"0">>, proplists:get_value(<<"grpc-status">>, Trailers)),
    _ = h2:close(Client).

%% One large message round-trips intact, exercising client send chunking and
%% receive reassembly + flow control (WINDOW_UPDATE both ways) against the real
%% server. 256 KiB exceeds the default 64 KiB window.
large_message_flow_control_test(Config) ->
    Port = server_port(?config(server, Config)),
    {ok, Client} = connect(Port),
    ok = h2:wait_connected(Client),
    {ok, Sid} = open_grpc_stream(Client, Port),
    Big = crypto:strong_rand_bytes(256 * 1024),
    {Echoed, Trailers} = grpc_bidi(Client, Sid, [Big], 20000),
    ?assertEqual([Big], Echoed),
    ?assertEqual(<<"0">>, proplists:get_value(<<"grpc-status">>, Trailers)),
    _ = h2:close(Client).

%% ============================================================================
%% gRPC client glue (no protobuf: identity-serialized bytes both ways)
%% ============================================================================

connect(Port) ->
    h2:connect("127.0.0.1", Port, #{transport => tcp}).

open_grpc_stream(Client, Port) ->
    Headers = [{<<":method">>, <<"POST">>},
               {<<":scheme">>, <<"http">>},
               {<<":path">>, <<"/echo.Echo/BidiStream">>},
               {<<":authority">>, authority(Port)},
               {<<"content-type">>, <<"application/grpc">>},
               {<<"te">>, <<"trailers">>}],
    %% gRPC bidi: the server defers its response headers until the handler
    %% yields, which needs our first message - so we do NOT wait for the
    %% response here, only after sending. Returns the stream id.
    h2:request(Client, Headers, #{handler => self(), end_stream => false}).

%% Send each payload as a gRPC length-prefixed frame, half-close, then read the
%% response (200), echoed frames, and trailers.
grpc_bidi(Client, Sid, Payloads, Timeout) ->
    [ok = h2:send_data(Client, Sid, grpc_frame(P), false) || P <- Payloads],
    ok = h2:send_data(Client, Sid, <<>>, true),
    {Buf, Trailers} = collect_grpc(Client, Sid, <<>>, Timeout),
    {parse_grpc(Buf), Trailers}.

collect_grpc(Client, Sid, Acc, Timeout) ->
    receive
        {h2, Client, {response, Sid, 200, _}} ->
            collect_grpc(Client, Sid, Acc, Timeout);
        {h2, Client, {data, Sid, Data, _Fin}} ->
            collect_grpc(Client, Sid, <<Acc/binary, Data/binary>>, Timeout);
        {h2, Client, {trailers, Sid, Trailers}} ->
            {Acc, Trailers};
        {h2, Client, {response, Sid, Status, Hdrs}} ->
            error({grpc_http_status, Status, Hdrs});
        {h2, Client, {stream_reset, Sid, Code}} ->
            error({stream_reset, Code});
        {h2, Client, _Other} ->
            collect_grpc(Client, Sid, Acc, Timeout)
    after Timeout ->
        error({collect_grpc_timeout, byte_size(Acc)})
    end.

%% gRPC message framing (RFC: 1 compressed-flag byte + 4 length bytes + message).
grpc_frame(Payload) ->
    <<0:8, (byte_size(Payload)):32, Payload/binary>>.

parse_grpc(<<_Compressed:8, Len:32, Msg:Len/binary, Rest/binary>>) ->
    [Msg | parse_grpc(Rest)];
parse_grpc(<<>>) ->
    [].

authority(Port) ->
    iolist_to_binary([<<"127.0.0.1:">>, integer_to_binary(Port)]).

%% ============================================================================
%% grpc-python server lifecycle
%% ============================================================================

%% Try GRPC_PYTHON, then python3 / python on PATH; accept the first whose
%% interpreter can `import grpc`.
find_python() ->
    Candidates = [os:getenv("GRPC_PYTHON"), "python3", "python"],
    find_python([C || C <- Candidates, C =/= false]).

find_python([]) ->
    error;
find_python([Python | Rest]) ->
    case has_grpcio(Python) of
        true  -> {ok, Python};
        false -> find_python(Rest)
    end.

has_grpcio(Python) ->
    Exe = os:find_executable(Python),
    %% Detect via exit status, not stdout: a failing `python -c` echoes the
    %% source line in its traceback (Py 3.14+), so any sentinel printed would
    %% also appear there. The __RC=0 marker only shows on a clean import.
    Exe =/= false andalso
        string:find(os:cmd(Exe ++ " -c 'import grpc' 2>/dev/null; echo __RC=$?"),
                    "__RC=0") =/= nomatch.

write_server_script(Dir) ->
    Path = filename:join(Dir, "grpc_echo_server.py"),
    Script =
        "import sys\n"
        "import grpc\n"
        "from concurrent import futures\n"
        "\n"
        "def echo(request_iterator, context):\n"
        "    for msg in request_iterator:\n"
        "        yield msg\n"
        "\n"
        "handler = grpc.method_handlers_generic_handler(\n"
        "    'echo.Echo',\n"
        "    {'BidiStream': grpc.stream_stream_rpc_method_handler(\n"
        "        echo, request_deserializer=None, response_serializer=None)})\n"
        "server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))\n"
        "server.add_generic_rpc_handlers((handler,))\n"
        "port = server.add_insecure_port('127.0.0.1:0')\n"
        "server.start()\n"
        "sys.stdout.write('PORT=%d\\n' % port)\n"
        "sys.stdout.flush()\n"
        "server.wait_for_termination()\n",
    ok = file:write_file(Path, Script),
    Path.

start_grpc_server(Python, Script) ->
    Exe = os:find_executable(Python),
    EPort = erlang:open_port({spawn_executable, Exe},
                             [{args, [Script]}, {line, 256}, binary,
                              stderr_to_stdout, exit_status]),
    case read_port_number(EPort, []) of
        {ok, PortNum} ->
            OsPid = case erlang:port_info(EPort, os_pid) of
                {os_pid, P} -> P;
                _           -> undefined
            end,
            #{eport => EPort, os_pid => OsPid, port => PortNum};
        {error, Reason} ->
            ct:fail({grpc_server_start_failed, Reason})
    end.

read_port_number(EPort, Acc) ->
    receive
        {EPort, {data, {eol, Line}}} ->
            case Line of
                <<"PORT=", Rest/binary>> -> {ok, binary_to_integer(Rest)};
                _ -> read_port_number(EPort, [Line | Acc])
            end;
        {EPort, {data, {noeol, Chunk}}} ->
            read_port_number(EPort, [Chunk | Acc]);
        {EPort, {exit_status, Status}} ->
            {error, {exited, Status, lists:reverse(Acc)}}
    after 20000 ->
        {error, {timeout, lists:reverse(Acc)}}
    end.

server_port(#{port := Port}) -> Port.

stop_grpc_server(#{eport := EPort, os_pid := OsPid}) ->
    try erlang:port_close(EPort) catch _:_ -> ok end,
    case OsPid of
        undefined -> ok;
        _         -> _ = os:cmd("kill -9 " ++ integer_to_list(OsPid)), ok
    end.
