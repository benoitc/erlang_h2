%% @doc HTTP/2 Public API
%%
%% This module provides the public API for HTTP/2 client and server operations.
%% It wraps the h2_connection state machine with a clean interface.
%%
%% == Client Usage ==
%%
%% ```
%% %% Connect to a server
%% {ok, Conn} = h2:connect("example.com", 443, #{}).
%%
%% %% Send a request
%% {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [
%%     {<<"host">>, <<"example.com">>}
%% ]).
%%
%% %% Receive response (messages sent to caller)
%% receive
%%     {h2, Conn, {response, StreamId, Status, Headers}} ->
%%         io:format("Status: ~p~n", [Status]);
%%     {h2, Conn, {data, StreamId, Data, IsFin}} ->
%%         io:format("Data: ~p~n", [Data])
%% end.
%%
%% %% Close connection
%% ok = h2:close(Conn).
%% '''
%%
%% == Server Usage ==
%%
%% ```
%% %% Start server
%% {ok, Server} = h2:start_server(8443, #{
%%     cert => "server.pem",
%%     key => "server-key.pem",
%%     handler => fun(Conn, StreamId, Method, Path, Headers) ->
%%         h2:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
%%         h2:send_data(Conn, StreamId, <<"Hello World!">>, true)
%%     end
%% }).
%%
%% %% Stop server
%% ok = h2:stop_server(Server).
%% '''
%%
%% == Event Messages ==
%%
%% The owner process receives the following messages:
%%
%% Client:
%% - `{h2, Conn, {response, StreamId, Status, Headers}}'
%% - `{h2, Conn, {data, StreamId, Data, IsFin}}'
%% - `{h2, Conn, {trailers, StreamId, Trailers}}'
%% - `{h2, Conn, {stream_reset, StreamId, ErrorCode}}'
%% - `{h2, Conn, {goaway, LastStreamId, ErrorCode}}'
%% - `{h2, Conn, closed}'
%%
%% Server handler receives direct calls.
%%
-module(h2).

%% Client API
-export([connect/2, connect/3]).
-export([wait_connected/1, wait_connected/2]).
-export([request/2, request/3, request/4, request/5]).

%% Server API
-export([start_server/2, start_server/3, stop_server/1]).
-export([send_response/4]).

%% Common API
-export([send_data/3, send_data/4]).
-export([send_trailers/3]).
-export([cancel/2, cancel/3]).
-export([cancel_stream/2, cancel_stream/3]).
-export([goaway/1, goaway/2]).
-export([close/1]).
-export([get_settings/1, get_peer_settings/1]).
-export([controlling_process/2]).

%% Types
-type connection() :: pid().
-type stream_id() :: non_neg_integer().
-type headers() :: [{binary(), binary()}].
-type status() :: 100..599.
-type error_code() :: h2_error:error_code().
-type server_ref() :: {pid(), reference()}.

-type connect_opts() :: #{
    transport => tcp | ssl,
    ssl_opts => [ssl:tls_client_option()],
    cert => binary() | string(),
    key => binary() | string(),
    cacerts => [binary()],
    verify => verify_none | verify_peer,
    settings => h2_settings:settings(),
    timeout => timeout(),
    connect_timeout => timeout(),
    sync => boolean()
}.

-type server_opts() :: #{
    cert := binary() | string(),
    key := binary() | string(),
    cacerts => [binary()],
    handler := fun((connection(), stream_id(), binary(), binary(), headers()) -> any()),
    settings => h2_settings:settings(),
    acceptors => pos_integer()
}.

-export_type([connection/0, stream_id/0, headers/0, status/0, error_code/0]).
-export_type([connect_opts/0, server_opts/0, server_ref/0]).

%% ============================================================================
%% Client API
%% ============================================================================

%% @doc Connect to an HTTP/2 server.
%% Uses TLS by default on port 443.
-spec connect(string() | binary(), inet:port_number()) ->
    {ok, connection()} | {error, term()}.
connect(Host, Port) ->
    connect(Host, Port, #{}).

%% @doc Connect to an HTTP/2 server with options.
-spec connect(string() | binary(), inet:port_number(), connect_opts()) ->
    {ok, connection()} | {error, term()}.
connect(Host, Port, Opts) when is_binary(Host) ->
    connect(binary_to_list(Host), Port, Opts);
connect(Host, Port, Opts) ->
    Transport = maps:get(transport, Opts, ssl),
    Timeout = maps:get(timeout, Opts, 30000),

    case Transport of
        ssl ->
            connect_ssl(Host, Port, Opts, Timeout);
        tcp ->
            connect_tcp(Host, Port, Opts, Timeout)
    end.

connect_ssl(Host, Port, Opts, Timeout) ->
    DefaultSSLOpts = [
        {active, false},
        {mode, binary},
        {alpn_advertised_protocols, [<<"h2">>]},
        {versions, ['tlsv1.2', 'tlsv1.3']}
    ],
    SSLOpts0 = maps:get(ssl_opts, Opts, []),
    SSLOpts = merge_opts(DefaultSSLOpts, SSLOpts0),

    case ssl:connect(Host, Port, SSLOpts, Timeout) of
        {ok, Socket} ->
            %% Verify ALPN negotiated h2
            case ssl:negotiated_protocol(Socket) of
                {ok, <<"h2">>} ->
                    start_connection(client, Socket, Opts);
                {ok, Other} ->
                    ssl:close(Socket),
                    {error, {alpn_mismatch, Other}};
                {error, protocol_not_negotiated} ->
                    %% Continue anyway, assume h2
                    start_connection(client, Socket, Opts);
                {error, Reason} ->
                    ssl:close(Socket),
                    {error, {alpn_error, Reason}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

connect_tcp(Host, Port, Opts, Timeout) ->
    TCPOpts = [
        {active, false},
        {mode, binary},
        {packet, raw}
    ],
    case gen_tcp:connect(Host, Port, TCPOpts, Timeout) of
        {ok, Socket} ->
            start_connection(client, Socket, Opts);
        {error, Reason} ->
            {error, Reason}
    end.

start_connection(Mode, Socket, Opts) ->
    ConnOpts = maps:with([settings], Opts),
    Timeout = maps:get(timeout, Opts, 30000),
    case h2_connection:start_link(Mode, Socket, ConnOpts) of
        {ok, Pid} ->
            %% Transfer socket ownership to connection process
            Transport = case is_ssl_socket(Socket) of
                true -> ssl;
                false -> gen_tcp
            end,
            case Transport of
                ssl -> ssl:controlling_process(Socket, Pid);
                gen_tcp -> gen_tcp:controlling_process(Socket, Pid)
            end,
            %% Activate the socket now that ownership is transferred
            h2_connection:activate(Pid),
            %% Wait for connection to complete handshake
            case h2_connection:wait_connected(Pid, Timeout) of
                ok ->
                    {ok, Pid};
                {error, Reason} ->
                    catch h2_connection:close(Pid),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

is_ssl_socket(Socket) when is_tuple(Socket) ->
    element(1, Socket) =:= sslsocket;
is_ssl_socket(_) ->
    false.

%% @doc Wait for a client connection to reach the connected state.
-spec wait_connected(connection()) -> ok | {error, term()}.
wait_connected(Conn) ->
    h2_connection:wait_connected(Conn).

-spec wait_connected(connection(), timeout()) -> ok | {error, term()}.
wait_connected(Conn, Timeout) ->
    h2_connection:wait_connected(Conn, Timeout).

%% @doc Send an HTTP/2 request with pre-built headers (matches quic_h3:request/2).
%% Headers should include pseudo-headers (:method, :path, :scheme, :authority).
-spec request(connection(), headers()) ->
    {ok, stream_id()} | {error, term()}.
request(Conn, Headers) ->
    request(Conn, Headers, #{}).

-spec request(connection(), headers(), map()) ->
    {ok, stream_id()} | {error, term()}.
request(Conn, Headers, Opts) ->
    EndStream = maps:get(end_stream, Opts, true),
    h2_connection:send_request_headers(Conn, Headers, EndStream).

%% @doc Send an HTTP/2 request.
%% For requests without a body (GET, HEAD, etc.), this sends HEADERS with END_STREAM.
-spec request(connection(), binary(), binary(), headers()) ->
    {ok, stream_id()} | {error, term()}.
request(Conn, Method, Path, Headers) ->
    h2_connection:send_request(Conn, Method, Path, Headers, true).

%% @doc Send an HTTP/2 request with body.
%% Sends HEADERS without END_STREAM, then sends DATA with END_STREAM.
-spec request(connection(), binary(), binary(), headers(), binary()) ->
    {ok, stream_id()} | {error, term()}.
request(Conn, Method, Path, Headers, Body) ->
    case h2_connection:send_request(Conn, Method, Path, Headers, false) of
        {ok, StreamId} ->
            case h2_connection:send_data(Conn, StreamId, Body, true) of
                ok -> {ok, StreamId};
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%% ============================================================================
%% Server API
%% ============================================================================

%% @doc Start a named HTTP/2 server (matches quic_h3:start_server/3).
-spec start_server(atom(), inet:port_number(), server_opts()) ->
    {ok, server_ref()} | {error, term()}.
start_server(Name, Port, Opts) when is_atom(Name) ->
    case start_server(Port, Opts) of
        {ok, Ref} ->
            persistent_term:put({?MODULE, server, Name}, Ref),
            {ok, Ref};
        Other ->
            Other
    end.

%% @doc Start an HTTP/2 server.
-spec start_server(inet:port_number(), server_opts()) ->
    {ok, server_ref()} | {error, term()}.
start_server(Port, Opts) ->
    %% Validate required options
    case {maps:find(cert, Opts), maps:find(key, Opts), maps:find(handler, Opts)} of
        {{ok, Cert}, {ok, Key}, {ok, Handler}} ->
            NumAcceptors = maps:get(acceptors, Opts, erlang:system_info(schedulers)),
            Settings = maps:get(settings, Opts, #{}),
            CACerts = maps:get(cacerts, Opts, []),

            %% Load certificates
            CertFile = load_file(Cert),
            KeyFile = load_file(Key),

            SSLOpts = [
                {certfile, CertFile},
                {keyfile, KeyFile},
                {alpn_preferred_protocols, [<<"h2">>]},
                {versions, ['tlsv1.2', 'tlsv1.3']},
                {reuseaddr, true}
            ] ++ case CACerts of
                [] -> [];
                _ -> [{cacerts, CACerts}, {verify, verify_peer}]
            end,

            %% Start listener
            case ssl:listen(Port, SSLOpts) of
                {ok, ListenSocket} ->
                    %% Create server state
                    Ref = make_ref(),
                    ServerState = #{
                        listen_socket => ListenSocket,
                        handler => Handler,
                        settings => Settings,
                        ref => Ref
                    },

                    %% Start acceptor processes
                    Self = self(),
                    AcceptorPids = [spawn_link(fun() ->
                        acceptor_loop(Self, ServerState)
                    end) || _ <- lists:seq(1, NumAcceptors)],

                    %% Start server manager process
                    ManagerPid = spawn_link(fun() ->
                        server_manager_loop(ListenSocket, AcceptorPids, Ref)
                    end),

                    {ok, {ManagerPid, Ref}};
                {error, Reason} ->
                    {error, {listen_failed, Reason}}
            end;
        _ ->
            {error, {missing_required_option, [cert, key, handler]}}
    end.

%% @doc Stop an HTTP/2 server.
-spec stop_server(server_ref()) -> ok.
stop_server({ManagerPid, Ref}) ->
    ManagerPid ! {stop, Ref},
    ok.

server_manager_loop(ListenSocket, AcceptorPids, Ref) ->
    receive
        {stop, Ref} ->
            %% Stop all acceptors
            lists:foreach(fun(Pid) -> exit(Pid, shutdown) end, AcceptorPids),
            ssl:close(ListenSocket),
            ok;
        {'EXIT', Pid, _Reason} ->
            %% Acceptor died, remove from list
            NewPids = lists:delete(Pid, AcceptorPids),
            server_manager_loop(ListenSocket, NewPids, Ref);
        _ ->
            server_manager_loop(ListenSocket, AcceptorPids, Ref)
    end.

acceptor_loop(Owner, #{listen_socket := ListenSocket, handler := Handler, settings := Settings} = State) ->
    case ssl:transport_accept(ListenSocket, infinity) of
        {ok, Socket} ->
            case ssl:handshake(Socket, 30000) of
                {ok, SSLSocket} ->
                    %% Check ALPN
                    case ssl:negotiated_protocol(SSLSocket) of
                        {ok, <<"h2">>} ->
                            %% Ensure socket is in passive mode before transfer
                            ssl:setopts(SSLSocket, [{active, false}]),
                            %% Start connection handler
                            %% First spawn the process, then transfer socket ownership to it
                            Pid = spawn_link(fun() ->
                                receive
                                    {socket_ready, Sock} ->
                                        handle_server_connection(Sock, Handler, Settings)
                                end
                            end),
                            ssl:controlling_process(SSLSocket, Pid),
                            Pid ! {socket_ready, SSLSocket};
                        _ ->
                            ssl:close(SSLSocket)
                    end;
                {error, _} ->
                    ok
            end,
            acceptor_loop(Owner, State);
        {error, closed} ->
            ok;
        {error, _Reason} ->
            acceptor_loop(Owner, State)
    end.

handle_server_connection(Socket, Handler, Settings) ->
    ConnOpts = #{settings => Settings},
    case h2_connection:start_link(server, Socket, self(), ConnOpts) of
        {ok, Conn} ->
            ssl:controlling_process(Socket, Conn),
            h2_connection:activate(Conn),
            server_connection_loop(Conn, Handler);
        {error, _Reason} ->
            ssl:close(Socket)
    end.

server_connection_loop(Conn, Handler) ->
    receive
        {h2, Conn, {request, StreamId, Method, Path, Headers}} ->
            %% Spawn handler for this request
            spawn(fun() ->
                try
                    Handler(Conn, StreamId, Method, Path, Headers)
                catch
                    Class:Reason:Stack ->
                        error_logger:error_msg("Handler error: ~p:~p~n~p~n", [Class, Reason, Stack]),
                        catch h2:send_response(Conn, StreamId, 500, []),
                        catch h2:send_data(Conn, StreamId, <<"Internal Server Error">>, true)
                end
            end),
            server_connection_loop(Conn, Handler);
        {h2, Conn, {data, _StreamId, _Data, _IsFin}} ->
            %% Data received (for POST/PUT bodies)
            server_connection_loop(Conn, Handler);
        {h2, Conn, closed} ->
            ok;
        {h2, Conn, {goaway, _LastStreamId, _ErrorCode}} ->
            ok;
        _ ->
            server_connection_loop(Conn, Handler)
    end.

%% @doc Send an HTTP/2 response (server mode).
-spec send_response(connection(), stream_id(), status(), headers()) ->
    ok | {error, term()}.
send_response(Conn, StreamId, Status, Headers) ->
    h2_connection:send_response(Conn, StreamId, Status, Headers).

%% ============================================================================
%% Common API
%% ============================================================================

%% @doc Send data on a stream.
-spec send_data(connection(), stream_id(), binary()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data) ->
    h2_connection:send_data(Conn, StreamId, Data).

%% @doc Send data on a stream with end_stream flag.
-spec send_data(connection(), stream_id(), binary(), boolean()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data, EndStream) ->
    h2_connection:send_data(Conn, StreamId, Data, EndStream).

%% @doc Send trailers on a stream.
-spec send_trailers(connection(), stream_id(), headers()) -> ok | {error, term()}.
send_trailers(Conn, StreamId, Trailers) ->
    h2_connection:send_trailers(Conn, StreamId, Trailers).

%% @doc Cancel a stream.
-spec cancel(connection(), stream_id()) -> ok | {error, term()}.
cancel(Conn, StreamId) ->
    h2_connection:cancel_stream(Conn, StreamId).

%% @doc Cancel a stream with a specific error code.
-spec cancel(connection(), stream_id(), error_code()) -> ok | {error, term()}.
cancel(Conn, StreamId, ErrorCode) ->
    h2_connection:cancel_stream(Conn, StreamId, ErrorCode).

%% @doc Alias for cancel/2.
-spec cancel_stream(connection(), stream_id()) -> ok | {error, term()}.
cancel_stream(Conn, StreamId) ->
    cancel(Conn, StreamId).

%% @doc Alias for cancel/3.
-spec cancel_stream(connection(), stream_id(), error_code()) -> ok | {error, term()}.
cancel_stream(Conn, StreamId, ErrorCode) ->
    cancel(Conn, StreamId, ErrorCode).

%% @doc Initiate graceful connection shutdown.
-spec goaway(connection()) -> ok | {error, term()}.
goaway(Conn) ->
    h2_connection:send_goaway(Conn).

%% @doc Initiate connection shutdown with error code.
-spec goaway(connection(), error_code()) -> ok | {error, term()}.
goaway(Conn, ErrorCode) ->
    h2_connection:send_goaway(Conn, ErrorCode).

%% @doc Close the connection immediately.
-spec close(connection()) -> ok.
close(Conn) ->
    h2_connection:close(Conn).

%% @doc Get local settings.
-spec get_settings(connection()) -> h2_settings:settings().
get_settings(Conn) ->
    h2_connection:get_settings(Conn).

%% @doc Get peer settings.
-spec get_peer_settings(connection()) -> h2_settings:settings().
get_peer_settings(Conn) ->
    h2_connection:get_peer_settings(Conn).

%% @doc Transfer connection ownership.
-spec controlling_process(connection(), pid()) -> ok | {error, term()}.
controlling_process(Conn, NewOwner) ->
    h2_connection:controlling_process(Conn, NewOwner).

%% ============================================================================
%% Internal Functions
%% ============================================================================

merge_opts(Default, Override) ->
    lists:ukeymerge(1,
        lists:ukeysort(1, Override),
        lists:ukeysort(1, Default)).

load_file(Path) when is_list(Path) -> Path;
load_file(Path) when is_binary(Path) -> binary_to_list(Path).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

merge_opts_test() ->
    Default = [{a, 1}, {b, 2}],
    Override = [{b, 3}, {c, 4}],
    Merged = merge_opts(Default, Override),
    ?assertEqual(1, proplists:get_value(a, Merged)),
    ?assertEqual(3, proplists:get_value(b, Merged)),
    ?assertEqual(4, proplists:get_value(c, Merged)).

-endif.
