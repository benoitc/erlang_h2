%% @doc HTTP/2 Connection State Machine (RFC 7540)
%%
%% This module implements the HTTP/2 connection protocol using gen_statem.
%% It handles both client and server modes, managing the connection preface,
%% settings exchange, stream lifecycle, flow control, and frame dispatch.
%%
%% States:
%% - preface: Exchanging connection preface
%% - settings: Exchanging SETTINGS frames
%% - connected: Ready for requests/responses
%% - goaway_sent: Graceful shutdown initiated by us
%% - goaway_received: Peer initiated shutdown
%% - closing: Connection closing
%%
-module(h2_connection).
-behaviour(gen_statem).

%% API
-export([start_link/3, start_link/4]).
-export([activate/1]).
-export([wait_connected/1, wait_connected/2]).
-export([send_request/4, send_request/5, send_request_headers/3, send_response/4, send_data/3, send_data/4]).
-export([set_stream_handler/3, set_stream_handler/4, unset_stream_handler/2]).
-export([send_trailers/3]).
-export([cancel_stream/2, cancel_stream/3]).
-export([send_goaway/1, send_goaway/2, close/1]).
-export([get_settings/1, get_peer_settings/1]).
-export([controlling_process/2]).

%% gen_statem callbacks
-export([init/1, callback_mode/0, terminate/3, code_change/4]).
-export([preface/3, settings/3, connected/3, goaway_sent/3, goaway_received/3, closing/3]).

-include("h2.hrl").

-define(SETTINGS_TIMEOUT_MS, 5000).
-define(CLOSE_TIMEOUT_MS, 5000).
-define(GOAWAY_DRAIN_MS, 100).

%% Stream states per RFC 7540 Section 5.1
-record(stream, {
    id :: non_neg_integer(),
    state = idle :: idle | open | half_closed_local | half_closed_remote | closed | reserved_local | reserved_remote,
    window_size :: integer(),
    recv_window_size :: integer(),
    send_buffer = <<>> :: binary(),
    pending_end_stream = false :: boolean(),
    header_buffer = [] :: iodata(),
    request_headers = [] :: [{binary(), binary()}],
    response_headers = [] :: [{binary(), binary()}],
    %% Optional pid to receive body data for this stream (set_stream_handler).
    handler :: pid() | undefined,
    %% Data buffered before a handler is registered.
    recv_buffer = [] :: [{binary(), boolean()}],
    %% RFC 7540 §8.3: stream is a CONNECT tunnel — DATA frames carry raw
    %% bytes, END_STREAM is half-close, no trailers, no CL/TE on response.
    tunnel = false :: boolean(),
    %% RFC 9113 §8.1.1 body-length tracking:
    %% expected = parsed Content-Length (undefined if header absent).
    %% received = cumulative DATA payload size (flow-controlled).
    %% body_forbidden = HEAD request / 1xx / 204 / 304 response → no DATA allowed.
    %% Set once on initial HEADERS, used in handle_data_frame/5.
    expected_body_length :: undefined | non_neg_integer(),
    received_body_length = 0 :: non_neg_integer(),
    body_forbidden = false :: boolean(),
    %% Set once the client's initial (2xx+) response HEADERS has been dispatched.
    %% Interim 1xx responses do NOT set this; subsequent HEADERS after it are trailers.
    response_seen_final = false :: boolean(),
    %% Request method, captured server-side to decide body-forbidden and tunnel rules.
    request_method :: undefined | binary(),
    %% RFC 8441: Extended CONNECT protocol token (e.g. <<"websocket">>).
    %% Set when the request carries a `:protocol` pseudo-header.
    protocol :: undefined | binary()
}).

%% Connection state
-record(state, {
    mode :: client | server,
    socket :: gen_tcp:socket() | ssl:sslsocket(),
    transport :: gen_tcp | ssl,
    owner :: pid(),
    buffer = <<>> :: binary(),

    %% Settings
    local_settings :: h2_settings:settings(),
    peer_settings :: h2_settings:settings(),
    pending_settings = [] :: [h2_settings:settings()],

    %% Cached peer settings values accessed on every frame / new stream.
    %% Refreshed whenever peer_settings changes (apply_peer_settings/2).
    peer_max_frame_size = ?DEFAULT_MAX_FRAME_SIZE :: non_neg_integer(),
    peer_initial_window_size = ?DEFAULT_INITIAL_WINDOW_SIZE :: integer(),
    peer_max_concurrent_streams = ?DEFAULT_MAX_CONCURRENT_STREAMS :: non_neg_integer() | unlimited,

    %% HPACK contexts
    encode_context :: h2_hpack:context(),
    decode_context :: h2_hpack:context(),

    %% Streams
    streams = #{} :: #{non_neg_integer() => #stream{}},
    next_stream_id :: non_neg_integer(),  % 1 for client, 2 for server
    last_peer_stream_id = 0 :: non_neg_integer(),

    %% Flow control
    conn_window_size :: integer(),       % Our send window
    recv_conn_window_size :: integer(),  % Our receive window

    %% State tracking
    preface_received = false :: boolean(),
    settings_acked = false :: boolean(),
    goaway_sent = false :: boolean(),
    goaway_received = false :: boolean(),
    last_stream_id = 0 :: non_neg_integer(),
    goaway_error = no_error :: atom(),

    %% Timers
    settings_timer :: reference() | undefined,
    close_timer :: reference() | undefined,

    %% Callers waiting for connected state
    waiters = [] :: [gen_statem:from()],

    %% RFC 7540 §6.10: once HEADERS/PUSH_PROMISE/CONTINUATION without
    %% END_HEADERS arrives, the only frame we may accept until
    %% END_HEADERS is a matching CONTINUATION on the same stream.
    %% {StreamId, EndStream} while awaiting; undefined otherwise.
    expecting_continuation :: {non_neg_integer(), boolean()} | undefined,

    %% Scheme to advertise on outbound :scheme pseudo-header.
    %% Derived from transport at init: ssl -> https, gen_tcp -> http.
    scheme = <<"https">> :: binary(),

    %% RFC 8441: when true, server advertises SETTINGS_ENABLE_CONNECT_PROTOCOL=1
    %% and accepts requests with the `:protocol` pseudo-header. Server-side opt-in.
    enable_connect_protocol = false :: boolean()
}).

%% ============================================================================
%% API Functions
%% ============================================================================

%% @doc Start a connection as a client.
-spec start_link(client, gen_tcp:socket() | ssl:sslsocket(), map()) -> {ok, pid()} | {error, term()}.
start_link(client, Socket, Opts) ->
    start_link(client, Socket, self(), Opts).

%% @doc Start a connection with explicit owner.
-spec start_link(client | server, gen_tcp:socket() | ssl:sslsocket(), pid(), map()) -> {ok, pid()} | {error, term()}.
start_link(Mode, Socket, Owner, Opts) ->
    gen_statem:start_link(?MODULE, {Mode, Socket, Owner, Opts}, []).

%% @doc Wait for the connection to reach connected state.
-spec wait_connected(pid()) -> ok | {error, term()}.
wait_connected(Conn) ->
    wait_connected(Conn, 30000).

%% @doc Wait for the connection to reach connected state with timeout.
-spec wait_connected(pid(), timeout()) -> ok | {error, term()}.
wait_connected(Conn, Timeout) ->
    try
        gen_statem:call(Conn, wait_connected, Timeout)
    catch
        exit:{Reason, _} -> {error, Reason};
        exit:Reason -> {error, Reason}
    end.

%% @doc Activate the socket after ownership transfer.
%% Must be called after transferring socket ownership to this process.
%% Synchronous so the caller knows the preface + SETTINGS have been sent and
%% the socket has been set to active mode before it proceeds.
-spec activate(pid()) -> ok | {error, term()}.
activate(Conn) ->
    gen_statem:call(Conn, activate).

%% @doc Send a request (client mode).
-spec send_request(pid(), binary(), binary(), [{binary(), binary()}]) ->
    {ok, non_neg_integer()} | {error, term()}.
send_request(Conn, Method, Path, Headers) ->
    send_request(Conn, Method, Path, Headers, true).

%% @doc Send a request with EndStream flag (client mode).
-spec send_request(pid(), binary(), binary(), [{binary(), binary()}], boolean()) ->
    {ok, non_neg_integer()} | {error, term()}.
send_request(Conn, Method, Path, Headers, EndStream) ->
    gen_statem:call(Conn, {send_request, Method, Path, Headers, EndStream}).

%% @doc Send a request with a pre-built header list (including pseudo-headers).
-spec send_request_headers(pid(), [{binary(), binary()}], boolean()) ->
    {ok, non_neg_integer()} | {error, term()}.
send_request_headers(Conn, Headers, EndStream) ->
    gen_statem:call(Conn, {send_request_headers, Headers, EndStream}).

%% @doc Register a pid to receive body data for StreamId.
%% Matches quic_h3:set_stream_handler/3,4.
-spec set_stream_handler(pid(), non_neg_integer(), pid()) ->
    ok | {ok, [{binary(), boolean()}]} | {error, term()}.
set_stream_handler(Conn, StreamId, Pid) ->
    set_stream_handler(Conn, StreamId, Pid, #{}).

-spec set_stream_handler(pid(), non_neg_integer(), pid(), map()) ->
    ok | {ok, [{binary(), boolean()}]} | {error, term()}.
set_stream_handler(Conn, StreamId, Pid, Opts) ->
    gen_statem:call(Conn, {set_stream_handler, StreamId, Pid, Opts}).

-spec unset_stream_handler(pid(), non_neg_integer()) -> ok.
unset_stream_handler(Conn, StreamId) ->
    gen_statem:call(Conn, {unset_stream_handler, StreamId}).

%% @doc Send a response (server mode).
-spec send_response(pid(), non_neg_integer(), non_neg_integer(), [{binary(), binary()}]) ->
    ok | {error, term()}.
send_response(Conn, StreamId, Status, Headers) ->
    gen_statem:call(Conn, {send_response, StreamId, Status, Headers}).

%% @doc Send data on a stream.
-spec send_data(pid(), non_neg_integer(), binary()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data) ->
    send_data(Conn, StreamId, Data, false).

%% @doc Send data on a stream with end_stream flag.
-spec send_data(pid(), non_neg_integer(), binary(), boolean()) -> ok | {error, term()}.
send_data(Conn, StreamId, Data, EndStream) ->
    gen_statem:call(Conn, {send_data, StreamId, Data, EndStream}).

%% @doc Send trailers on a stream.
-spec send_trailers(pid(), non_neg_integer(), [{binary(), binary()}]) -> ok | {error, term()}.
send_trailers(Conn, StreamId, Trailers) ->
    gen_statem:call(Conn, {send_trailers, StreamId, Trailers}).

%% @doc Cancel a stream.
-spec cancel_stream(pid(), non_neg_integer()) -> ok | {error, term()}.
cancel_stream(Conn, StreamId) ->
    cancel_stream(Conn, StreamId, cancel).

%% @doc Cancel a stream with a specific error code.
-spec cancel_stream(pid(), non_neg_integer(), atom()) -> ok | {error, term()}.
cancel_stream(Conn, StreamId, ErrorCode) ->
    gen_statem:call(Conn, {cancel_stream, StreamId, ErrorCode}).

%% @doc Send GOAWAY frame.
-spec send_goaway(pid()) -> ok | {error, term()}.
send_goaway(Conn) ->
    send_goaway(Conn, no_error).

%% @doc Send GOAWAY frame with error code.
-spec send_goaway(pid(), atom()) -> ok | {error, term()}.
send_goaway(Conn, ErrorCode) ->
    gen_statem:call(Conn, {send_goaway, ErrorCode}).

%% @doc Close the connection.
-spec close(pid()) -> ok.
close(Conn) ->
    gen_statem:stop(Conn).

%% @doc Get local settings.
-spec get_settings(pid()) -> h2_settings:settings().
get_settings(Conn) ->
    gen_statem:call(Conn, get_settings).

%% @doc Get peer settings.
-spec get_peer_settings(pid()) -> h2_settings:settings().
get_peer_settings(Conn) ->
    gen_statem:call(Conn, get_peer_settings).

%% @doc Transfer ownership of the connection.
-spec controlling_process(pid(), pid()) -> ok | {error, term()}.
controlling_process(Conn, NewOwner) ->
    gen_statem:call(Conn, {controlling_process, NewOwner}).

%% ============================================================================
%% gen_statem Callbacks
%% ============================================================================

callback_mode() -> [state_functions, state_enter].

init({Mode, Socket, Owner, Opts}) ->
    process_flag(trap_exit, true),

    %% Determine transport
    Transport = case is_ssl_socket(Socket) of
        true -> ssl;
        false -> gen_tcp
    end,

    %% Initialize settings.
    %% RFC 9113 §6.5.2: a server MUST NOT advertise SETTINGS_ENABLE_PUSH=1.
    %% We don't implement push as either client or server, so always 0.
    UserSettings = maps:get(settings, Opts, #{}),
    EnableConnectProtocol = Mode =:= server
                            andalso maps:get(enable_connect_protocol, Opts, false) =:= true,
    %% RFC 8441 §3: server opts in by sending SETTINGS_ENABLE_CONNECT_PROTOCOL=1.
    ConnectProtoSettings = case EnableConnectProtocol of
        true  -> #{enable_connect_protocol => 1};
        false -> #{}
    end,
    LocalSettings = maps:merge(
        maps:merge(h2_settings:default(), UserSettings),
        ConnectProtoSettings#{enable_push => 0}),
    PeerSettings = h2_settings:default(),

    %% Scheme depends on transport: TCP → http, TLS → https.
    Scheme = case Transport of
        ssl     -> <<"https">>;
        gen_tcp -> <<"http">>
    end,

    %% Initialize HPACK contexts
    EncodeCtx = h2_hpack:new_context(h2_settings:get(header_table_size, PeerSettings)),
    DecodeCtx = h2_hpack:new_context(h2_settings:get(header_table_size, LocalSettings)),

    %% Initialize flow control
    InitialWindow = h2_settings:get(initial_window_size, PeerSettings),
    RecvWindow = h2_settings:get(initial_window_size, LocalSettings),

    State = #state{
        mode = Mode,
        socket = Socket,
        transport = Transport,
        owner = Owner,
        local_settings = LocalSettings,
        peer_settings = PeerSettings,
        peer_max_frame_size = h2_settings:get(max_frame_size, PeerSettings),
        peer_initial_window_size = h2_settings:get(initial_window_size, PeerSettings),
        peer_max_concurrent_streams = h2_settings:get(max_concurrent_streams, PeerSettings),
        encode_context = EncodeCtx,
        decode_context = DecodeCtx,
        next_stream_id = case Mode of client -> 1; server -> 2 end,
        conn_window_size = InitialWindow,
        recv_conn_window_size = RecvWindow,
        scheme = Scheme,
        enable_connect_protocol = EnableConnectProtocol
    },

    %% Note: Socket is NOT set to active here - it will be activated
    %% in the preface state after socket ownership is properly transferred.
    %% The caller must transfer socket ownership before the connection can receive data.

    {ok, preface, State}.

terminate(Reason, _StateName, #state{socket = Socket, transport = Transport, goaway_sent = GoawaySent} = State) ->
    %% Send GOAWAY if not already sent
    case GoawaySent of
        false ->
            Frame = h2_frame:goaway(0, no_error, <<>>),
            _ = Transport:send(Socket, h2_frame:encode(Frame));
        true ->
            ok
    end,
    Transport:close(Socket),
    %% Notify owner exactly once that the connection is gone.
    notify_owner({h2, self(), {closed, peel_reason(Reason)}}, State),
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%% ============================================================================
%% State: preface
%% ============================================================================

preface(enter, _OldState, State) ->
    %% Don't send preface/settings yet - wait for socket activation
    %% The caller will transfer socket ownership and call activate
    {keep_state, State};

preface(info, {tcp, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(preface, Data, State);
preface(info, {ssl, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(preface, Data, State);

preface(info, {tcp_closed, Socket}, #state{socket = Socket} = State) ->
    stop_and_notify_waiters({shutdown, tcp_closed}, State);
preface(info, {ssl_closed, Socket}, #state{socket = Socket} = State) ->
    stop_and_notify_waiters({shutdown, ssl_closed}, State);

preface(info, {tcp_error, Socket, Reason}, #state{socket = Socket} = State) ->
    stop_and_notify_waiters({shutdown, {tcp_error, Reason}}, State);
preface(info, {ssl_error, Socket, Reason}, #state{socket = Socket} = State) ->
    stop_and_notify_waiters({shutdown, {ssl_error, Reason}}, State);

preface(info, {timeout, Timer, settings_timeout}, #state{settings_timer = Timer} = State) ->
    %% Peer didn't respond in time
    State1 = send_goaway_frame(0, settings_timeout, State),
    {next_state, closing, State1};

preface({call, From}, activate, #state{mode = Mode, transport = Transport, socket = Socket} = State) ->
    %% Socket ownership has been transferred, now we can send and receive.
    case set_active(Transport, Socket) of
        ok ->
            State1 = case Mode of
                client -> send_preface(State);
                server -> send_settings_frame(State)
            end,
            Timer = erlang:start_timer(?SETTINGS_TIMEOUT_MS, self(), settings_timeout),
            {keep_state, State1#state{settings_timer = Timer},
             [{reply, From, ok}]};
        {error, Reason} ->
            {stop_and_reply, {shutdown, {socket_error, Reason}},
             [{reply, From, {error, Reason}}], State}
    end;

preface({call, From}, Request, State) ->
    %% Queue or reject requests until connected
    handle_call_early(From, Request, preface, State);

preface(EventType, Event, State) ->
    handle_common(EventType, Event, preface, State).

%% ============================================================================
%% State: settings
%% ============================================================================

settings(enter, _OldState, State) ->
    {keep_state, State};

settings(info, {tcp, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(settings, Data, State);
settings(info, {ssl, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(settings, Data, State);

settings(info, {tcp_closed, Socket}, #state{socket = Socket} = State) ->
    stop_and_notify_waiters({shutdown, tcp_closed}, State);
settings(info, {ssl_closed, Socket}, #state{socket = Socket} = State) ->
    stop_and_notify_waiters({shutdown, ssl_closed}, State);

settings(info, {timeout, Timer, settings_timeout}, #state{settings_timer = Timer} = State) ->
    State1 = send_goaway_frame(0, settings_timeout, State),
    {next_state, closing, State1};

settings({call, From}, activate, State) ->
    %% Already activated on transition out of preface; idempotent.
    {keep_state, State, [{reply, From, ok}]};

settings({call, From}, Request, State) ->
    handle_call_early(From, Request, settings, State);

settings(EventType, Event, State) ->
    handle_common(EventType, Event, settings, State).

%% ============================================================================
%% State: connected
%% ============================================================================

connected(enter, _OldState, #state{settings_timer = Timer, waiters = Waiters} = State) ->
    %% Cancel settings timer if still running
    case Timer of
        undefined -> ok;
        _ -> _ = erlang:cancel_timer(Timer), ok
    end,
    %% Notify owner that connection is ready
    notify_owner({h2, self(), connected}, State),
    %% Reply to all waiters
    Replies = [{reply, From, ok} || From <- Waiters],
    {keep_state, State#state{settings_timer = undefined, waiters = []}, Replies};

connected(info, {tcp, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(connected, Data, State);
connected(info, {ssl, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(connected, Data, State);

connected(info, {tcp_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, {shutdown, tcp_closed}, State};
connected(info, {ssl_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, {shutdown, ssl_closed}, State};

connected({call, From}, {send_request, Method, Path, Headers, EndStream}, State) ->
    handle_send_request(From, Method, Path, Headers, EndStream, State);

connected({call, From}, {send_request_headers, Headers, EndStream}, State) ->
    handle_send_request_headers(From, Headers, EndStream, State);

connected({call, From}, {send_response, StreamId, Status, Headers}, State) ->
    handle_send_response(From, StreamId, Status, Headers, State);

connected({call, From}, {send_data, StreamId, Data, EndStream}, State) ->
    handle_send_data(From, StreamId, Data, EndStream, State);

connected({call, From}, {send_trailers, StreamId, Trailers}, State) ->
    handle_send_trailers(From, StreamId, Trailers, State);

connected({call, From}, {cancel_stream, StreamId, ErrorCode}, State) ->
    handle_cancel_stream(From, StreamId, ErrorCode, State);

connected({call, From}, {set_stream_handler, StreamId, Pid, Opts}, State) ->
    handle_set_stream_handler(From, StreamId, Pid, Opts, State);

connected({call, From}, {unset_stream_handler, StreamId}, State) ->
    handle_unset_stream_handler(From, StreamId, State);

connected({call, From}, {send_goaway, ErrorCode}, State) ->
    handle_send_goaway(From, ErrorCode, connected, State);

connected({call, From}, wait_connected, State) ->
    %% Already connected, reply immediately
    {keep_state, State, [{reply, From, ok}]};

connected({call, From}, Request, State) ->
    handle_call_common(From, Request, connected, State);

connected(EventType, Event, State) ->
    handle_common(EventType, Event, connected, State).

%% ============================================================================
%% State: goaway_sent
%% ============================================================================

goaway_sent(enter, _OldState, #state{close_timer = Timer} = State) when Timer =/= undefined ->
    %% Drain timer already armed by handle_send_goaway.
    {keep_state, State};
goaway_sent(enter, _OldState, State) ->
    %% No drain timer (e.g. internally-triggered error GOAWAY) — close soon.
    Timer = erlang:start_timer(?CLOSE_TIMEOUT_MS, self(), close_timeout),
    {keep_state, State#state{close_timer = Timer}};

goaway_sent(info, {tcp, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(goaway_sent, Data, State);
goaway_sent(info, {ssl, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(goaway_sent, Data, State);

goaway_sent(info, {tcp_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, {shutdown, tcp_closed}, State};
goaway_sent(info, {ssl_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, {shutdown, ssl_closed}, State};

goaway_sent(info, {timeout, Timer, goaway_drain},
            #state{close_timer = Timer, last_peer_stream_id = LastId,
                   goaway_error = ErrorCode} = State) ->
    %% Drain window elapsed — send the real GOAWAY with the actual last
    %% peer-initiated stream id and close.
    State1 = send_goaway_frame(LastId, ErrorCode, State#state{close_timer = undefined}),
    {stop, {shutdown, goaway_drained}, State1};

goaway_sent(info, {timeout, Timer, close_timeout}, #state{close_timer = Timer} = State) ->
    {stop, {shutdown, close_timeout}, State};

goaway_sent({call, From}, {send_data, StreamId, Data, EndStream}, State) ->
    %% Allow completing existing streams
    handle_send_data(From, StreamId, Data, EndStream, State);

goaway_sent({call, From}, {send_request, _, _, _, _}, State) ->
    {keep_state, State, [{reply, From, {error, goaway_sent}}]};
goaway_sent({call, From}, {send_request_headers, _, _}, State) ->
    {keep_state, State, [{reply, From, {error, goaway_sent}}]};

goaway_sent({call, From}, Request, State) ->
    handle_call_common(From, Request, goaway_sent, State);

goaway_sent(EventType, Event, State) ->
    handle_common(EventType, Event, goaway_sent, State).

%% ============================================================================
%% State: goaway_received
%% ============================================================================

goaway_received(enter, _OldState, State) ->
    {keep_state, State};

goaway_received(info, {tcp, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(goaway_received, Data, State);
goaway_received(info, {ssl, Socket, Data}, #state{socket = Socket} = State) ->
    handle_data(goaway_received, Data, State);

goaway_received(info, {tcp_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, {shutdown, tcp_closed}, State};
goaway_received(info, {ssl_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, {shutdown, ssl_closed}, State};

goaway_received({call, From}, {send_data, StreamId, Data, EndStream}, State) ->
    %% Allow completing existing streams
    handle_send_data(From, StreamId, Data, EndStream, State);

goaway_received({call, From}, Request, State) ->
    handle_call_common(From, Request, goaway_received, State);

goaway_received(EventType, Event, State) ->
    handle_common(EventType, Event, goaway_received, State).

%% ============================================================================
%% State: closing
%% ============================================================================

closing(enter, _OldState, State) ->
    %% Start close timer
    Timer = erlang:start_timer(?CLOSE_TIMEOUT_MS, self(), close_timeout),
    {keep_state, State#state{close_timer = Timer}};

closing(info, {tcp_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, {shutdown, tcp_closed}, State};
closing(info, {ssl_closed, Socket}, #state{socket = Socket} = State) ->
    {stop, {shutdown, ssl_closed}, State};

closing(info, {timeout, Timer, close_timeout}, #state{close_timer = Timer} = State) ->
    {stop, {shutdown, close_timeout}, State};

closing(info, {tcp, _Socket, _Data}, State) ->
    %% Ignore incoming data
    {keep_state, State};
closing(info, {ssl, _Socket, _Data}, State) ->
    {keep_state, State};

closing({call, From}, _, State) ->
    {keep_state, State, [{reply, From, {error, closing}}]};

closing(EventType, Event, State) ->
    handle_common(EventType, Event, closing, State).

%% ============================================================================
%% Internal: Data Handling
%% ============================================================================

handle_data(StateName, Data, #state{buffer = Buffer, mode = Mode, preface_received = PrefaceReceived} = State) ->
    DataBin = iolist_to_binary(Data),
    NewBuffer = <<Buffer/binary, DataBin/binary>>,
    State1 = State#state{buffer = NewBuffer},

    %% Check for preface if server and not yet received
    case Mode of
        server when not PrefaceReceived ->
            case check_preface(NewBuffer) of
                {ok, Rest} ->
                    State2 = State1#state{buffer = Rest, preface_received = true},
                    process_frames(StateName, State2);
                need_more ->
                    ok = set_active(State1#state.transport, State1#state.socket),
                    {keep_state, State1};
                {error, Reason} ->
                    State2 = send_goaway_frame(0, protocol_error, State1),
                    {stop, {shutdown, {preface_error, Reason}}, State2}
            end;
        _ ->
            process_frames(StateName, State1)
    end.

check_preface(Buffer) when byte_size(Buffer) < ?H2_PREFACE_SIZE ->
    need_more;
check_preface(Buffer) ->
    case Buffer of
        <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Rest/binary>> ->
            {ok, Rest};
        _ ->
            {error, invalid_preface}
    end.

process_frames(StateName, #state{buffer = Buffer, local_settings = Local} = State) ->
    MaxFrameSize = h2_settings:get(max_frame_size, Local),
    case h2_frame:decode(Buffer, MaxFrameSize) of
        {ok, Frame, Rest} ->
            case handle_frame(StateName, Frame, State#state{buffer = Rest}) of
                {ok, NewStateName, NewState} ->
                    process_frames(NewStateName, NewState);
                {stop, Reason, NewState} ->
                    {stop, Reason, NewState};
                {error, ErrorCode, NewState} ->
                    NewState1 = send_goaway_frame(NewState#state.last_peer_stream_id, ErrorCode, NewState),
                    {next_state, closing, NewState1}
            end;
        {more, _Needed} ->
            ok = set_active(State#state.transport, State#state.socket),
            %% Determine the correct state based on connection conditions
            determine_state_transition(State);
        {error, {stream_error, StreamId, ErrorCode}, Rest} ->
            %% Frame-level decode error scoped to a single stream
            %% (e.g. WINDOW_UPDATE 0 on a non-zero stream id).
            send_rst_stream(StreamId, ErrorCode, State),
            State1 = close_stream(StreamId, State),
            process_frames(StateName, State1#state{buffer = Rest});
        {error, Reason} ->
            State1 = send_goaway_frame(State#state.last_peer_stream_id, Reason, State),
            {next_state, closing, State1}
    end.

%% Determine the correct state based on connection conditions
determine_state_transition(#state{mode = Mode, preface_received = PrefaceReceived,
                                   settings_acked = SettingsAcked} = State) ->
    %% For client: connected when we've received and acked peer's settings,
    %% and received ack for our settings
    %% For server: connected when preface received, settings exchanged
    case Mode of
        client ->
            case SettingsAcked of
                true -> {next_state, connected, State};
                false -> {next_state, settings, State}
            end;
        server ->
            case {PrefaceReceived, SettingsAcked} of
                {true, true} -> {next_state, connected, State};
                {true, false} -> {next_state, settings, State};
                {false, _} -> {keep_state, State}
            end
    end.

%% ============================================================================
%% Internal: Frame Handling
%% ============================================================================

%% RFC 7540 §6.10: while awaiting CONTINUATION, only a CONTINUATION on the
%% same stream is allowed. Anything else is a connection PROTOCOL_ERROR.
handle_frame(_StateName, Frame, #state{expecting_continuation = {StreamId, _}} = State)
  when element(1, Frame) =/= continuation ->
    _ = StreamId,
    {error, protocol_error, State};
handle_frame(_StateName, {continuation, StreamId, _, _}, #state{expecting_continuation = {Expected, _}} = State)
  when StreamId =/= Expected ->
    {error, protocol_error, State};

handle_frame(_StateName, {settings, Settings}, State) ->
    handle_settings(Settings, State);

handle_frame(_StateName, {settings_ack}, #state{pending_settings = [Pending|Rest]} = State) ->
    %% Apply our pending settings
    State1 = apply_local_settings(Pending, State),
    State2 = State1#state{pending_settings = Rest, settings_acked = true},
    NewStateName = case State2#state.preface_received orelse State2#state.mode == client of
        true -> connected;
        false -> settings
    end,
    {ok, NewStateName, State2};
handle_frame(_StateName, {settings_ack}, State) ->
    %% Unexpected ACK - ignore
    {ok, connected, State};

handle_frame(_StateName, {ping, Data}, State) ->
    %% Respond with PING ACK
    Frame = h2_frame:ping_ack(Data),
    send_frame(Frame, State),
    {ok, connected, State};

handle_frame(_StateName, {ping_ack, _Data}, State) ->
    %% PING response received
    {ok, connected, State};

handle_frame(StateName, {goaway, LastStreamId, ErrorCodeInt, _DebugData}, State) ->
    ErrorCode = h2_error:name(ErrorCodeInt),
    notify_owner({h2, self(), {goaway, LastStreamId, ErrorCode}}, State),
    State1 = State#state{goaway_received = true, last_stream_id = LastStreamId},
    case StateName of
        goaway_sent -> {stop, {shutdown, goaway_exchange}, State1};
        _ -> {ok, goaway_received, State1}
    end;

handle_frame(_StateName, {window_update, 0, Increment}, #state{conn_window_size = Window} = State) ->
    NewWindow = Window + Increment,
    if
        NewWindow > ?MAX_WINDOW_SIZE ->
            {error, flow_control_error, State};
        true ->
            %% Try to send buffered data
            State1 = State#state{conn_window_size = NewWindow},
            State2 = flush_send_buffers(State1),
            {ok, connected, State2}
    end;

handle_frame(_StateName, {window_update, StreamId, Increment}, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{window_size = Window} = Stream} ->
            NewWindow = Window + Increment,
            if
                NewWindow > ?MAX_WINDOW_SIZE ->
                    send_rst_stream(StreamId, flow_control_error, State),
                    State1 = close_stream(StreamId, State),
                    {ok, connected, State1};
                true ->
                    Stream1 = Stream#stream{window_size = NewWindow},
                    State1 = State#state{streams = maps:put(StreamId, Stream1, Streams)},
                    State2 = flush_stream_buffer(StreamId, State1),
                    {ok, connected, State2}
            end;
        error ->
            %% Ignore window update for unknown/closed stream
            {ok, connected, State}
    end;

handle_frame(_StateName, {headers, StreamId, HeaderBlock, EndStream, EndHeaders}, State) ->
    handle_headers(StreamId, HeaderBlock, EndStream, EndHeaders, undefined, State);

handle_frame(_StateName, {headers, StreamId, HeaderBlock, EndStream, EndHeaders, Priority}, State) ->
    handle_headers(StreamId, HeaderBlock, EndStream, EndHeaders, Priority, State);

handle_frame(_StateName, {continuation, StreamId, HeaderBlock, EndHeaders}, State) ->
    handle_continuation(StreamId, HeaderBlock, EndHeaders, State);

handle_frame(_StateName, {data, StreamId, Data, EndStream, FlowControlled}, State) ->
    handle_data_frame(StreamId, Data, EndStream, FlowControlled, State);

handle_frame(_StateName, {rst_stream, StreamId, ErrorCode},
             #state{streams = Streams} = State) ->
    %% RFC 7540 §6.4 / §5.1: RST_STREAM on an "idle" stream (one that was
    %% never opened by either side) is a connection PROTOCOL_ERROR.
    case maps:is_key(StreamId, Streams) orelse in_closed_stream_range(StreamId, State) of
        true ->
            notify_stream(StreamId, {stream_reset, StreamId, h2_error:name(ErrorCode)}, State),
            State1 = close_stream(StreamId, State),
            {ok, connected, State1};
        false ->
            {error, protocol_error, State}
    end;

handle_frame(_StateName, {priority, _StreamId, _Exclusive, _DependsOn, _Weight}, State) ->
    %% Priority is advisory, ignore
    {ok, connected, State};

handle_frame(_StateName, {push_promise, _StreamId, _PromisedId, _HeaderBlock, _EndHeaders}, State) ->
    %% We don't support server push, send GOAWAY
    {error, protocol_error, State}.

%% ============================================================================
%% Internal: Settings Handling
%% ============================================================================

handle_settings(Settings, #state{peer_settings = OldSettings} = State) ->
    %% Decode and validate settings
    case h2_settings:decode(encode_settings_list(Settings)) of
        {ok, NewSettings} ->
            case h2_settings:validate(NewSettings) of
                ok ->
                    %% Merge and apply
                    MergedSettings = h2_settings:merge(OldSettings, NewSettings),
                    case apply_peer_settings(MergedSettings, State) of
                        {ok, State1} ->
                            send_frame(h2_frame:settings_ack(), State1),
                            NewStateName = case State1#state.settings_acked of
                                true -> connected;
                                false -> settings
                            end,
                            {ok, NewStateName, State1};
                        {error, ErrCode} ->
                            {error, ErrCode, State}
                    end;
                {error, _Reason} ->
                    {error, protocol_error, State}
            end;
        {error, _Reason} ->
            {error, protocol_error, State}
    end.

encode_settings_list(Settings) ->
    lists:foldl(fun({Id, Value}, Acc) ->
        <<Acc/binary, Id:16, Value:32>>
    end, <<>>, Settings).

apply_peer_settings(Settings, #state{encode_context = EncCtx, streams = Streams,
                                      peer_settings = OldSettings} = State) ->
    NewTableSize = h2_settings:get(header_table_size, Settings),
    EncCtx1 = h2_hpack:set_max_table_size(NewTableSize, EncCtx),

    OldWindow = h2_settings:get(initial_window_size, OldSettings),
    NewWindow = h2_settings:get(initial_window_size, Settings),
    Delta = NewWindow - OldWindow,
    %% RFC 7540 §6.9.2: if the change makes any stream's flow-control window
    %% exceed 2^31-1, treat as connection FLOW_CONTROL_ERROR.
    Overflow = maps:fold(fun(_Id, #stream{window_size = W}, Acc) ->
        Acc orelse (W + Delta) > ?MAX_WINDOW_SIZE
    end, false, Streams),
    case Overflow of
        true ->
            {error, flow_control_error};
        false ->
            Streams1 = maps:map(fun(_Id, #stream{window_size = W} = S) ->
                S#stream{window_size = W + Delta}
            end, Streams),
            {ok, State#state{
                peer_settings = Settings,
                peer_max_frame_size = h2_settings:get(max_frame_size, Settings),
                peer_initial_window_size = NewWindow,
                peer_max_concurrent_streams = h2_settings:get(max_concurrent_streams, Settings),
                encode_context = EncCtx1,
                streams = Streams1
            }}
    end.

apply_local_settings(Settings, #state{decode_context = DecCtx, local_settings = Prev} = State) ->
    %% Update HPACK decoder table size
    NewTableSize = h2_settings:get(header_table_size, Settings),
    OldTableSize = h2_settings:get(header_table_size, Prev),
    DecCtx1 = h2_hpack:set_max_table_size(NewTableSize, DecCtx),
    %% RFC 7541 §6.3: peer-advertised limit (= our SETTINGS_HEADER_TABLE_SIZE)
    %% caps any size update the peer's encoder may send.
    DecCtx1a = h2_hpack:set_peer_max_table_size(NewTableSize, DecCtx1),
    %% RFC 7541 §4.2: when we reduce HEADER_TABLE_SIZE, the peer's next
    %% header block MUST start with a size update at or below the new max.
    DecCtx2 = case NewTableSize < OldTableSize of
        true -> h2_hpack:mark_pending_size_update(DecCtx1a);
        false -> DecCtx1a
    end,
    State#state{
        local_settings = Settings,
        decode_context = DecCtx2
    }.

%% ============================================================================
%% Internal: Headers Handling
%% ============================================================================

handle_headers(StreamId, HeaderBlock, EndStream, EndHeaders, _Priority, #state{mode = Mode, streams = Streams} = State) ->
    %% Check if this is a response on an existing stream or a new stream
    case maps:find(StreamId, Streams) of
        {ok, #stream{state = StreamState} = Stream}
          when StreamState =:= open; StreamState =:= half_closed_local ->
            %% Existing stream — response (client) or trailers
            case EndHeaders of
                true ->
                    decode_and_process_headers(StreamId, HeaderBlock, EndStream, State);
                false ->
                    Stream1 = Stream#stream{header_buffer = HeaderBlock},
                    State1 = put_stream(StreamId, Stream1, State),
                    State2 = State1#state{expecting_continuation = {StreamId, EndStream}},
                    {ok, connected, State2}
            end;
        {ok, _Stream} ->
            %% RFC 7540 §6.2: HEADERS MUST NOT be sent on a half-closed-remote
            %% or closed stream → stream error STREAM_CLOSED.
            send_rst_stream(StreamId, stream_closed, State),
            {ok, connected, State};
        error ->
            %% New stream - validate stream ID
            case validate_stream_id(StreamId, Mode, State) of
                ok ->
                    case EndHeaders of
                        true ->
                            decode_and_process_headers(StreamId, HeaderBlock, EndStream, State);
                        false ->
                            Stream = get_or_create_stream(StreamId, State),
                            Stream1 = Stream#stream{header_buffer = HeaderBlock},
                            State1 = put_stream(StreamId, Stream1, State),
                            State2 = State1#state{expecting_continuation = {StreamId, EndStream}},
                            {ok, connected, State2}
                    end;
                {error, ErrorCode} ->
                    {error, ErrorCode, State}
            end
    end.

handle_continuation(StreamId, HeaderBlock, EndHeaders,
                    #state{streams = Streams,
                           expecting_continuation = Expecting} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{header_buffer = Buffer} = Stream} ->
            NewBuffer = [Buffer, HeaderBlock],
            case EndHeaders of
                true ->
                    Stream1 = Stream#stream{header_buffer = []},
                    State1 = put_stream(StreamId, Stream1, State),
                    %% Restore the original END_STREAM flag captured when
                    %% HEADERS arrived; clear expecting_continuation.
                    EndStream = case Expecting of
                        {_, E} -> E;
                        _ -> false
                    end,
                    State2 = State1#state{expecting_continuation = undefined},
                    decode_and_process_headers(StreamId, iolist_to_binary(NewBuffer), EndStream, State2);
                false ->
                    Stream1 = Stream#stream{header_buffer = NewBuffer},
                    State1 = put_stream(StreamId, Stream1, State),
                    {ok, connected, State1}
            end;
        error ->
            {error, protocol_error, State}
    end.

decode_and_process_headers(StreamId, HeaderBlock, EndStream, #state{decode_context = DecCtx, mode = Mode} = State) ->
    case h2_hpack:decode(HeaderBlock, DecCtx) of
        {ok, Headers, DecCtx1} ->
            State1 = State#state{decode_context = DecCtx1},
            %% RFC 9113 §6.5.2: enforce our advertised MAX_HEADER_LIST_SIZE.
            case check_local_max_header_list_size(Headers, State1) of
                {error, _} ->
                    send_rst_stream(StreamId, protocol_error, State1),
                    State2 = case maps:is_key(StreamId, State1#state.streams) of
                        true -> close_stream(StreamId, State1);
                        false -> State1
                    end,
                    {ok, connected, State2};
                ok ->
                    decode_and_process_headers_validated(Mode, StreamId, Headers, EndStream, State1)
            end;
        {error, Reason} ->
            error_logger:error_msg("HPACK decode error: ~p~n", [Reason]),
            {error, compression_error, State}
    end.

decode_and_process_headers_validated(Mode, StreamId, Headers, EndStream, State1) ->
            %% Determine role of this HEADERS block:
            %%   initial  — first HEADERS on the stream (request or response).
            %%   interim  — 1xx response (client only), more HEADERS to follow.
            %%   trailers — after initial request body or after final response.
            Kind = classify_headers(Mode, StreamId, Headers, State1),
            IsTunnel = case maps:find(StreamId, State1#state.streams) of
                {ok, #stream{tunnel = T}} -> T;
                _ -> false
            end,
            Validation = case {Kind, IsTunnel} of
                {trailers, true} -> {error, protocol_error};  %% §8.3
                {trailers, false} -> validate_trailers(Headers, EndStream);
                {_, _} -> validate_initial_headers(Mode, Headers)
            end,
            case Validation of
                ok ->
                    decode_and_process_headers_cont(Kind, StreamId, Headers, EndStream, State1);
                {error, ValidErr} ->
                    send_rst_stream(StreamId, ValidErr, State1),
                    State2 = case maps:is_key(StreamId, State1#state.streams) of
                        true -> close_stream(StreamId, State1);
                        false -> State1
                    end,
                    {ok, connected, State2}
            end.

classify_headers(server, StreamId, _Headers, State) ->
    case maps:find(StreamId, State#state.streams) of
        {ok, #stream{request_method = undefined}} -> initial;
        error -> initial;
        {ok, _} -> trailers
    end;
classify_headers(client, StreamId, Headers, State) ->
    case maps:find(StreamId, State#state.streams) of
        {ok, #stream{response_seen_final = true}} -> trailers;
        {ok, _} ->
            case parse_status(Headers) of
                {ok, S} when S >= 100, S =< 199 -> interim;
                _ -> initial
            end;
        error -> initial
    end.

decode_and_process_headers_cont(Kind, StreamId, Headers, EndStream, #state{mode = Mode} = State) ->
    Stream = get_or_create_stream(StreamId, State),
    dispatch_headers(Mode, Kind, StreamId, Stream, Headers, EndStream, State).

%% Server receives the initial request HEADERS on a new stream.
dispatch_headers(server, initial, StreamId, Stream, Headers, EndStream, State) ->
    Protocol = proplists:get_value(<<":protocol">>, Headers),
    case extended_connect_allowed(Protocol, State) of
        false -> stream_reject(StreamId, protocol_error, State);
        true  -> handle_server_initial(StreamId, Stream, Headers, Protocol, EndStream, State)
    end;

%% Server receives trailing HEADERS closing a request body.
dispatch_headers(server, trailers, StreamId, _Stream, _Headers, false, State) ->
    %% RFC 9113 §8.1: trailers MUST carry END_STREAM.
    stream_reject(StreamId, protocol_error, State);
dispatch_headers(server, trailers, StreamId, Stream, Headers, true, State) ->
    deliver_trailers(StreamId, Stream, Headers, State, fun notify_stream/3);

%% Client receives a 1xx informational response. Stream stays open.
%% RFC 9113 §8.1 / RFC 9110 §15.2: interim responses MUST NOT carry END_STREAM
%% and MUST NOT carry content (Content-Length is meaningless).
dispatch_headers(client, interim, StreamId, _Stream, _Headers, true, State) ->
    stream_reject_and_close(StreamId, protocol_error, State);
dispatch_headers(client, interim, StreamId, _Stream, Headers, false, State) ->
    case proplists:is_defined(<<"content-length">>, Headers) of
        true ->
            stream_reject_and_close(StreamId, protocol_error, State);
        false ->
            {ok, Status} = parse_status(Headers),
            notify_owner({h2, self(), {informational, StreamId, Status, strip_pseudo(Headers)}}, State),
            {ok, connected, State}
    end;

%% Client receives the final response HEADERS.
dispatch_headers(client, initial, StreamId, Stream, Headers, EndStream, State) ->
    case parse_status(Headers) of
        malformed    -> stream_reject_and_close(StreamId, protocol_error, State);
        {ok, Status} -> handle_client_initial(StreamId, Stream, Headers, Status, EndStream, State)
    end;

%% Client receives trailing HEADERS closing a response body.
dispatch_headers(client, trailers, StreamId, Stream, Headers, _EndStream, State) ->
    deliver_trailers(StreamId, Stream, Headers, State, fun notify_owner_stream/3).

%% ---- Initial-HEADERS handlers ------------------------------------------------

handle_server_initial(StreamId, Stream, Headers, Protocol, EndStream, State) ->
    case parse_content_length(Headers) of
        {error, Err} ->
            stream_reject(StreamId, Err, State);
        {ok, ExpectedCL} ->
            case end_stream_body_mismatch(ExpectedCL, EndStream) of
                true ->
                    %% RFC 9113 §8.1: END_STREAM + CL>0 is malformed.
                    stream_reject(StreamId, protocol_error, State);
                false ->
                    commit_server_initial(StreamId, Stream, Headers, Protocol,
                                          ExpectedCL, EndStream, State)
            end
    end.

commit_server_initial(StreamId, Stream, Headers, Protocol, ExpectedCL, EndStream, State) ->
    {Method, Path, OtherHeaders} = extract_request_headers(Headers),
    %% RFC 7540 §8.3: a CONNECT stream becomes a tunnel only once the 2xx
    %% response is sent. Keep tunnel=false here; handle_send_response flips it.
    Stream1 = Stream#stream{
        state = stream_state_after_end(EndStream),
        request_headers = Headers,
        request_method = Method,
        tunnel = false,
        protocol = Protocol,
        expected_body_length = ExpectedCL,
        body_forbidden = Method =:= <<"HEAD">>
    },
    State1 = put_stream(StreamId, Stream1, State),
    State2 = State1#state{last_peer_stream_id =
                            max(StreamId, State1#state.last_peer_stream_id)},
    notify_owner({h2, self(), {request, StreamId, Method, Path, OtherHeaders}}, State2),
    {ok, connected, State2}.

handle_client_initial(StreamId, Stream, Headers, Status, EndStream, State) ->
    case parse_content_length(Headers) of
        {error, Err} ->
            stream_reject(StreamId, Err, State);
        {ok, ExpectedCL} ->
            BodyForbidden = Stream#stream.request_method =:= <<"HEAD">>
                            orelse Status =:= 204 orelse Status =:= 304,
            %% RFC 7540 §8.3: stream becomes a tunnel only on a 2xx response
            %% to a CONNECT request.
            IsTunnel = Stream#stream.request_method =:= <<"CONNECT">>
                       andalso Status >= 200 andalso Status < 300,
            Stream1 = Stream#stream{
                state = stream_state_after_end(EndStream),
                response_headers = Headers,
                response_seen_final = true,
                tunnel = IsTunnel,
                expected_body_length = ExpectedCL,
                body_forbidden = BodyForbidden
            },
            State1 = put_stream(StreamId, Stream1, State),
            notify_owner({h2, self(), {response, StreamId, Status, strip_pseudo(Headers)}}, State1),
            finalize_client_initial(StreamId, EndStream, ExpectedCL, State1)
    end.

%% Body continues arriving as DATA frames.
finalize_client_initial(_StreamId, false, _ExpectedCL, State) ->
    {ok, connected, State};
%% END_STREAM with CL>0 is a malformed response.
finalize_client_initial(StreamId, true, ExpectedCL, State)
  when ExpectedCL =/= undefined, ExpectedCL > 0 ->
    stream_reject_and_close(StreamId, protocol_error, State);
%% Body-less response (HEAD / 204 / 304 / empty): emit a trailing empty
%% DATA event so clients waiting on end-of-stream don't hang. Matches quic_h3.
finalize_client_initial(StreamId, true, _ExpectedCL, State) ->
    notify_stream(StreamId, {data, StreamId, <<>>, true}, State),
    {ok, connected, close_stream(StreamId, State)}.

%% ---- Shared helpers ---------------------------------------------------------

deliver_trailers(StreamId, Stream, Headers, State, NotifyFun) ->
    Stream1 = Stream#stream{state = closed},
    State1  = put_stream(StreamId, Stream1, State),
    NotifyFun(StreamId, {trailers, StreamId, Headers}, State1),
    {ok, connected, close_stream(StreamId, State1)}.

%% Uniform 3-arity shim so `deliver_trailers` can dispatch either fan-out style.
notify_owner_stream(_StreamId, Event, State) ->
    notify_owner({h2, self(), Event}, State).

%% RFC 8441 §4: a server that has not advertised SETTINGS_ENABLE_CONNECT_PROTOCOL=1
%% MUST treat a request carrying `:protocol` as malformed.
extended_connect_allowed(undefined, _State) -> true;
extended_connect_allowed(_Proto, #state{enable_connect_protocol = Flag}) -> Flag.

end_stream_body_mismatch(undefined, _EndStream) -> false;
end_stream_body_mismatch(CL, true) when CL > 0  -> true;
end_stream_body_mismatch(_, _)                  -> false.

stream_state_after_end(true)  -> half_closed_remote;
stream_state_after_end(false) -> open.

strip_pseudo(Headers) ->
    lists:filter(fun({N, _}) -> not is_pseudo_header(N) end, Headers).

stream_reject(StreamId, ErrorCode, State) ->
    send_rst_stream(StreamId, ErrorCode, State),
    {ok, connected, State}.

stream_reject_and_close(StreamId, ErrorCode, State) ->
    send_rst_stream(StreamId, ErrorCode, State),
    {ok, connected, close_stream(StreamId, State)}.

%% RFC 9113 §8.1.1: Content-Length parser. Multiple headers with the same
%% value collapse into one; mismatched values are malformed. Non-numeric or
%% negative values are malformed.
parse_content_length(Headers) ->
    Values = [V || {<<"content-length">>, V} <- Headers],
    case lists:usort(Values) of
        [] ->
            {ok, undefined};
        [Single] ->
            case parse_nonneg_integer(Single) of
                {ok, N} -> {ok, N};
                error -> {error, protocol_error}
            end;
        _ ->
            {error, protocol_error}
    end.

parse_nonneg_integer(Bin) ->
    try binary_to_integer(Bin) of
        N when N >= 0 -> {ok, N};
        _ -> error
    catch
        _:_ -> error
    end.

%% Validate an initial request/response HEADERS block per RFC 7540 §8.1.2.
%% Checks: pseudo-header order/set/duplicates, lowercase header names,
%% connection-specific headers, TE header restriction, :path syntax
%% (requests), :authority vs Host consistency (requests).
validate_initial_headers(Mode, Headers) ->
    Checks = [
        fun() -> check_pseudo_order(Headers) end,
        fun() -> check_pseudo_set(Mode, Headers) end,
        fun() -> check_lowercase_names(Headers) end,
        fun() -> check_connection_headers(Headers) end,
        fun() -> check_request_specific(Mode, Headers) end
    ],
    run_checks(Checks).

%% Validate a trailing HEADERS block per RFC 7540 §8.1:
%% MUST have END_STREAM and MUST NOT contain any pseudo-header.
validate_trailers(Headers, true) ->
    Checks = [
        fun() -> check_no_pseudo_in_trailers(Headers) end,
        fun() -> check_lowercase_names(Headers) end,
        fun() -> check_connection_headers(Headers) end
    ],
    run_checks(Checks);
validate_trailers(_Headers, false) ->
    {error, protocol_error}.

run_checks([]) -> ok;
run_checks([F | Rest]) ->
    case F() of
        ok -> run_checks(Rest);
        Err -> Err
    end.

check_no_pseudo_in_trailers(Headers) ->
    case [N || {<<$:, _/binary>> = N, _} <- Headers] of
        [] -> ok;
        _ -> {error, protocol_error}
    end.

%% RFC 9113 §8.2: field names are lowercase RFC 7230 tchar (pseudo-headers
%% start with ':'); values must not contain NUL/CR/LF nor have leading or
%% trailing SP/HTAB.
check_lowercase_names(Headers) ->
    Bad = lists:any(fun bad_field/1, Headers),
    case Bad of
        true -> {error, protocol_error};
        false -> ok
    end.

bad_field({<<>>, _}) -> true;
bad_field({<<$:, Rest/binary>>, Value}) ->
    %% Pseudo-header: rest must be lowercase tchar too.
    not valid_name_bytes(Rest) orelse bad_value(Value);
bad_field({Name, Value}) ->
    not valid_name_bytes(Name) orelse bad_value(Value).

%% Allowed bytes in a header field name: lowercase ALPHA, DIGIT, and
%%   !#$%&'*+-.^_`|~
valid_name_bytes(<<>>) -> true;
valid_name_bytes(<<C, Rest/binary>>) ->
    Ok = (C >= $a andalso C =< $z)
         orelse (C >= $0 andalso C =< $9)
         orelse lists:member(C, "!#$%&'*+-.^_`|~"),
    Ok andalso valid_name_bytes(Rest).

%% RFC 7230 §3.2.6 `token` — same alphabet as a header field name but
%% case-insensitive (uppercase also allowed). Used for RFC 8441 `:protocol`.
valid_token(<<>>)       -> false;
valid_token(Bin) when is_binary(Bin) -> valid_token_bytes(Bin);
valid_token(_)          -> false.

valid_token_bytes(<<>>) -> true;
valid_token_bytes(<<C, Rest/binary>>) ->
    Ok = (C >= $a andalso C =< $z)
         orelse (C >= $A andalso C =< $Z)
         orelse (C >= $0 andalso C =< $9)
         orelse lists:member(C, "!#$%&'*+-.^_`|~"),
    Ok andalso valid_token_bytes(Rest).

%% A value is bad if empty-after-trimming is fine, but leading/trailing SP/HTAB
%% or any NUL/CR/LF byte is forbidden.
bad_value(<<>>) -> false;
bad_value(<<C, _/binary>>) when C =:= $\s; C =:= $\t -> true;
bad_value(Bin) ->
    Last = binary:last(Bin),
    case Last of
        $\s -> true;
        $\t -> true;
        _ -> has_bad_value_byte(Bin)
    end.

has_bad_value_byte(<<>>) -> false;
has_bad_value_byte(<<0, _/binary>>) -> true;
has_bad_value_byte(<<$\n, _/binary>>) -> true;
has_bad_value_byte(<<$\r, _/binary>>) -> true;
has_bad_value_byte(<<_, Rest/binary>>) -> has_bad_value_byte(Rest).

%% RFC 7540 §8.1.2.2: reject connection-specific headers; TE only allowed with
%% the exact value "trailers".
check_connection_headers(Headers) ->
    Banned = [<<"connection">>, <<"proxy-connection">>, <<"keep-alive">>,
              <<"transfer-encoding">>, <<"upgrade">>, <<"host">>],
    %% We only ban Host as duplicate-check target, not here — Host handled in check_authority_host.
    BannedStrict = Banned -- [<<"host">>],
    Bad = lists:any(
        fun({Name, _}) -> lists:member(Name, BannedStrict) end, Headers),
    case Bad of
        true -> {error, protocol_error};
        false -> check_te_header(Headers)
    end.

check_te_header(Headers) ->
    case [V || {<<"te">>, V} <- Headers] of
        [] -> ok;
        [<<"trailers">>] -> ok;
        _ -> {error, protocol_error}
    end.

check_request_specific(server, Headers) ->
    Method = proplists:get_value(<<":method">>, Headers),
    case Method of
        undefined -> ok;  %% already caught in check_pseudo_set
        <<"CONNECT">> ->
            %% CONNECT has no :path/:scheme but :authority (no userinfo) still applies.
            check_authority_host(Headers);
        _ ->
            case check_path(Headers) of
                ok -> check_authority_host(Headers);
                Err -> Err
            end
    end;
check_request_specific(client, _Headers) ->
    ok.

check_path(Headers) ->
    case proplists:get_value(<<":path">>, Headers) of
        undefined -> ok;  %% already caught
        <<>> -> {error, protocol_error};
        Path ->
            case proplists:get_value(<<":scheme">>, Headers) of
                undefined -> ok;
                Scheme when Scheme =:= <<"http">>; Scheme =:= <<"https">> ->
                    Method = proplists:get_value(<<":method">>, Headers),
                    case {binary_part(Path, 0, 1), Method, Path} of
                        {<<"/">>, _, _} -> ok;
                        {<<"*">>, <<"OPTIONS">>, <<"*">>} -> ok;
                        _ -> {error, protocol_error}
                    end;
                _ -> ok
            end
    end.

check_authority_host(Headers) ->
    case proplists:get_value(<<":authority">>, Headers) of
        undefined -> ok;
        Authority ->
            %% RFC 9113 §8.3.1: `:authority` MUST NOT include the deprecated
            %% userinfo subcomponent for http/https schemes.
            case binary:match(Authority, <<"@">>) of
                nomatch -> check_host_consistency(Authority, Headers);
                _       -> {error, protocol_error}
            end
    end.

check_host_consistency(Authority, Headers) ->
    case proplists:get_value(<<"host">>, Headers) of
        undefined -> ok;
        Host ->
            case string:equal(Authority, Host, true) of
                true  -> ok;
                false -> {error, protocol_error}
            end
    end.

check_pseudo_order(Headers) ->
    check_pseudo_order(Headers, pseudo).

check_pseudo_order([], _) -> ok;
check_pseudo_order([{<<$:, _/binary>>, _} | Rest], pseudo) ->
    check_pseudo_order(Rest, pseudo);
check_pseudo_order([{<<$:, _/binary>>, _} | _], regular) ->
    {error, protocol_error};
check_pseudo_order([{_, _} | Rest], _) ->
    check_pseudo_order(Rest, regular).

check_pseudo_set(server, Headers) ->
    Pseudos = [N || {<<$:, _/binary>> = N, _} <- Headers],
    Uniq = lists:usort(Pseudos),
    case length(Pseudos) =:= length(Uniq) of
        false -> {error, protocol_error};
        true ->
            %% RFC 8441 §4: `:protocol` is allowed only with method CONNECT.
            Allowed = [<<":method">>, <<":scheme">>, <<":path">>, <<":authority">>,
                       <<":protocol">>],
            case [N || N <- Pseudos, not lists:member(N, Allowed)] of
                [] ->
                    Method = proplists:get_value(<<":method">>, Headers),
                    Protocol = proplists:get_value(<<":protocol">>, Headers),
                    case {Method, Protocol} of
                        {undefined, _} -> {error, protocol_error};
                        {_, undefined} when Method =:= <<"CONNECT">> ->
                            %% Vanilla CONNECT (RFC 7540 §8.3): `:authority`
                            %% required, `:scheme`/`:path` MUST be omitted.
                            HasScheme = proplists:is_defined(<<":scheme">>, Headers),
                            HasPath   = proplists:is_defined(<<":path">>, Headers),
                            case {proplists:get_value(<<":authority">>, Headers),
                                  HasScheme, HasPath} of
                                {undefined, _, _} -> {error, protocol_error};
                                {_, true, _} -> {error, protocol_error};
                                {_, _, true} -> {error, protocol_error};
                                _ -> ok
                            end;
                        {<<"CONNECT">>, _} ->
                            %% Extended CONNECT (RFC 8441 §4): `:method=CONNECT`
                            %% plus `:protocol` (RFC 7230 token), `:scheme`,
                            %% `:path`, `:authority` all REQUIRED.
                            case valid_token(Protocol) of
                                false -> {error, protocol_error};
                                true ->
                            case {proplists:get_value(<<":scheme">>, Headers),
                                  proplists:get_value(<<":path">>, Headers),
                                  proplists:get_value(<<":authority">>, Headers)} of
                                {undefined, _, _} -> {error, protocol_error};
                                {_, undefined, _} -> {error, protocol_error};
                                {_, <<>>, _} -> {error, protocol_error};
                                {_, _, undefined} -> {error, protocol_error};
                                _ -> ok
                            end
                            end;
                        {_, P} when P =/= undefined ->
                            %% `:protocol` without method CONNECT is malformed.
                            {error, protocol_error};
                        _ ->
                            case {proplists:get_value(<<":scheme">>, Headers),
                                  proplists:get_value(<<":path">>, Headers)} of
                                {undefined, _} -> {error, protocol_error};
                                {_, undefined} -> {error, protocol_error};
                                {_, <<>>} -> {error, protocol_error};
                                _ -> ok
                            end
                    end;
                _Unknown ->
                    {error, protocol_error}
            end
    end;
check_pseudo_set(client, Headers) ->
    Pseudos = [N || {<<$:, _/binary>> = N, _} <- Headers],
    Uniq = lists:usort(Pseudos),
    case length(Pseudos) =:= length(Uniq) of
        false -> {error, protocol_error};
        true ->
            case [N || N <- Pseudos, N =/= <<":status">>] of
                [] ->
                    case proplists:get_value(<<":status">>, Headers) of
                        undefined -> {error, protocol_error};
                        _ -> ok
                    end;
                _Unknown ->
                    {error, protocol_error}
            end
    end.

extract_request_headers(Headers) ->
    Method = proplists:get_value(<<":method">>, Headers, <<"GET">>),
    Path = proplists:get_value(<<":path">>, Headers, <<"/">>),
    %% Strip pseudo-headers from the user-visible list, except `:protocol`
    %% (RFC 8441) so handlers can read the Extended CONNECT protocol token.
    OtherHeaders = lists:filter(
        fun({<<":protocol">>, _}) -> true;
           ({N, _}) -> not is_pseudo_header(N)
        end, Headers),
    {Method, Path, OtherHeaders}.

%% RFC 9113 §8.3.2: :status MUST be present on a response HEADERS, exactly
%% three ASCII digits in the range 100..599. Anything else is a malformed
%% response and must trigger a stream PROTOCOL_ERROR.
parse_status(Headers) ->
    case proplists:get_value(<<":status">>, Headers) of
        %% RFC 9113 §8.6: HTTP/2 MUST NOT accept 101 Switching Protocols.
        <<"101">> -> malformed;
        <<D1, D2, D3>> when D1 >= $1, D1 =< $5, D2 >= $0, D2 =< $9, D3 >= $0, D3 =< $9 ->
            {ok, (D1 - $0) * 100 + (D2 - $0) * 10 + (D3 - $0)};
        _ ->
            malformed
    end.

%% RFC 9113 §6.5.2 / RFC 7541 §4.1: per-header overhead is 32 bytes plus the
%% name and value octets. Returns the advisory "header list size" sum.
header_list_size(Headers) ->
    lists:foldl(fun({N, V}, Acc) ->
        Acc + 32 + byte_size(N) + byte_size(V)
    end, 0, Headers).

%% Enforce peer-advertised SETTINGS_MAX_HEADER_LIST_SIZE before encoding.
check_peer_max_header_list_size(Headers, #state{peer_settings = PS}) ->
    case h2_settings:get(max_header_list_size, PS) of
        unlimited -> ok;
        Max when is_integer(Max) ->
            case header_list_size(Headers) > Max of
                true  -> {error, header_list_too_large};
                false -> ok
            end
    end.

%% Enforce our SETTINGS_MAX_HEADER_LIST_SIZE on received decoded headers.
check_local_max_header_list_size(Headers, #state{local_settings = LS}) ->
    case h2_settings:get(max_header_list_size, LS) of
        unlimited -> ok;
        Max when is_integer(Max) ->
            case header_list_size(Headers) > Max of
                true  -> {error, protocol_error};
                false -> ok
            end
    end.

%% RFC 9113 §8.1.1, §8.2: validate every outbound header block.
%% The existing Mode parameter of validate_initial_headers refers to the
%% *receiver*'s role (server validates requests, client validates responses),
%% so for outbound validation we flip: sending a request → server rules,
%% sending a response → client rules.
validate_outbound_request(Headers) ->
    validate_initial_headers(server, Headers).

validate_outbound_response(Headers) ->
    %% Status 101 already rejected before calling.
    validate_initial_headers(client, Headers).

is_pseudo_header(<<$:, _/binary>>) -> true;
is_pseudo_header(_) -> false.

%% ============================================================================
%% Internal: Data Frame Handling
%% ============================================================================

%% RFC 9113 §6.1: the receiver MUST count the full DATA payload (including
%% the pad length byte and any padding) against the connection-level flow
%% control window — *regardless* of stream state. Failing to consume post-
%% reset DATA desynchronizes the peer's accounting and lets it overshoot the
%% advertised receive window.
handle_data_frame(StreamId, Data, EndStream, FlowControlled,
                  #state{streams = Streams, recv_conn_window_size = ConnWindow} = State) ->
    if
        FlowControlled > ConnWindow ->
            %% Peer violated our advertised connection window.
            {error, flow_control_error, State};
        true ->
            State0 = State#state{recv_conn_window_size = ConnWindow - FlowControlled},
            State0a = maybe_send_conn_window_update(FlowControlled, State0),
            case maps:find(StreamId, Streams) of
                {ok, #stream{state = StreamState, recv_window_size = StreamWindow,
                             body_forbidden = BodyForbidden,
                             expected_body_length = ExpectedCL,
                             received_body_length = ReceivedSoFar,
                             tunnel = IsTunnel} = Stream} when StreamState == open; StreamState == half_closed_local ->
                    DataSize = byte_size(Data),
                    %% §8.1.1 body enforcement (not applicable to tunnels).
                    BodyViolation =
                        (not IsTunnel) andalso
                        ((BodyForbidden andalso DataSize > 0)
                         orelse (ExpectedCL =/= undefined andalso ReceivedSoFar + DataSize > ExpectedCL)
                         orelse (EndStream andalso ExpectedCL =/= undefined
                                 andalso ReceivedSoFar + DataSize =/= ExpectedCL)),
                    if
                        FlowControlled > StreamWindow ->
                            send_rst_stream(StreamId, flow_control_error, State0a),
                            State1 = close_stream(StreamId, State0a),
                            {ok, connected, State1};
                        BodyViolation ->
                            send_rst_stream(StreamId, protocol_error, State0a),
                            State1 = close_stream(StreamId, State0a),
                            {ok, connected, State1};
                        true ->
                            NewStreamWindow = StreamWindow - FlowControlled,
                            Stream1 = Stream#stream{
                                recv_window_size = NewStreamWindow,
                                received_body_length = ReceivedSoFar + DataSize
                            },

                            Stream2 = case EndStream of
                                true ->
                                    case StreamState of
                                        open -> Stream1#stream{state = half_closed_remote};
                                        half_closed_local -> Stream1#stream{state = closed}
                                    end;
                                false ->
                                    Stream1
                            end,

                            {Stream3, State1} = dispatch_data(StreamId, Stream2, Data, EndStream, State0a),
                            State2 = State1#state{
                                streams = maps:put(StreamId, Stream3, State1#state.streams)
                            },

                            State3 = maybe_send_window_update(StreamId, FlowControlled, State2),

                            case EndStream andalso Stream2#stream.state == closed of
                                true ->
                                    State4 = close_stream(StreamId, State3),
                                    {ok, connected, State4};
                                false ->
                                    {ok, connected, State3}
                            end
                    end;
                {ok, _} ->
                    send_rst_stream(StreamId, stream_closed, State0a),
                    {ok, connected, State0a};
                error ->
                    case in_closed_stream_range(StreamId, State0a) of
                        true ->
                            send_rst_stream(StreamId, stream_closed, State0a),
                            {ok, connected, State0a};
                        false ->
                            {error, protocol_error, State0a}
                    end
            end
    end.

in_closed_stream_range(StreamId, #state{mode = Mode, last_peer_stream_id = LastPeer,
                                         next_stream_id = NextLocal}) ->
    case Mode of
        client ->
            %% Peer-initiated (server) streams are even.
            StreamId rem 2 =:= 0 andalso StreamId =< LastPeer;
        server ->
            %% Peer-initiated (client) streams are odd; also allow our own
            %% (even) ids strictly below NextLocal as recently-closed.
            (StreamId rem 2 =:= 1 andalso StreamId =< LastPeer)
            orelse (StreamId rem 2 =:= 0 andalso StreamId < NextLocal)
    end.

%% Connection-level WINDOW_UPDATE refill. Called for every DATA frame,
%% including those on closed/unknown streams — per RFC 9113 §5.1 the
%% connection window is consumed regardless of stream state.
maybe_send_conn_window_update(_DataSize, #state{recv_conn_window_size = ConnWindow,
                                                 local_settings = Settings} = State) ->
    InitialWindow = h2_settings:get(initial_window_size, Settings),
    Threshold = InitialWindow div 2,
    case ConnWindow < Threshold of
        true ->
            ConnIncrement = InitialWindow - ConnWindow,
            send_frame(h2_frame:window_update(0, ConnIncrement), State),
            State#state{recv_conn_window_size = ConnWindow + ConnIncrement};
        false ->
            State
    end.

maybe_send_window_update(StreamId, _DataSize, #state{local_settings = Settings,
                                                     streams = Streams} = State) ->
    InitialWindow = h2_settings:get(initial_window_size, Settings),
    Threshold = InitialWindow div 2,
    case maps:find(StreamId, Streams) of
        {ok, #stream{recv_window_size = StreamWindow} = Stream} when StreamWindow < Threshold ->
            StreamIncrement = InitialWindow - StreamWindow,
            send_frame(h2_frame:window_update(StreamId, StreamIncrement), State),
            Stream1 = Stream#stream{recv_window_size = StreamWindow + StreamIncrement},
            State#state{streams = maps:put(StreamId, Stream1, Streams)};
        _ ->
            State
    end.

%% ============================================================================
%% Internal: Send Operations
%% ============================================================================

handle_send_request(From, Method, Path, Headers, EndStream, #state{mode = client, next_stream_id = StreamId,
                                                        peer_max_concurrent_streams = MaxStreams,
                                                        peer_initial_window_size = InitialWindow,
                                                        scheme = Scheme,
                                                        encode_context = EncCtx} = State) ->
    ActiveStreams = count_active_streams(State),

    case MaxStreams of
        N when is_integer(N), ActiveStreams >= N ->
            {keep_state, State, [{reply, From, {error, max_streams_exceeded}}]};
        _ ->
            IsConnect = Method =:= <<"CONNECT">>,
            Authority = proplists:get_value(<<"host">>, Headers, <<>>),
            %% RFC 7540 §8.3: CONNECT MUST omit :scheme and :path; :authority required.
            AllHeaders = case IsConnect of
                true ->
                    [{<<":method">>, Method},
                     {<<":authority">>, Authority}
                     | lists:filter(fun({N1, _}) -> N1 =/= <<"host">> end, Headers)];
                false ->
                    [{<<":method">>, Method},
                     {<<":path">>, Path},
                     {<<":scheme">>, Scheme},
                     {<<":authority">>, Authority}
                     | lists:filter(fun({N1, _}) -> N1 =/= <<"host">> end, Headers)]
            end,

            case validate_outbound_request(AllHeaders) of
                {error, _} = Err ->
                    {keep_state, State, [{reply, From, Err}]};
                ok ->
                    case check_peer_max_header_list_size(AllHeaders, State) of
                        {error, _} = SErr ->
                            {keep_state, State, [{reply, From, SErr}]};
                        ok ->
                    {HeaderBlock, EncCtx1} = h2_hpack:encode(AllHeaders, EncCtx),

                    RecvWindow = h2_settings:get(initial_window_size, State#state.local_settings),
                    StreamState = case EndStream of
                        true -> half_closed_local;
                        false -> open
                    end,
                    %% RFC 7540 §8.3: tunnel is only established on the 2xx
                    %% response; do NOT pre-set tunnel=true here. The client-side
                    %% flip happens in handle_client_initial.
                    Stream = #stream{
                        id = StreamId,
                        state = StreamState,
                        window_size = InitialWindow,
                        recv_window_size = RecvWindow,
                        tunnel = false,
                        request_method = Method
                    },

                    send_header_block(StreamId, HeaderBlock, EndStream, State),

                    State1 = State#state{
                        encode_context = EncCtx1,
                        streams = maps:put(StreamId, Stream, State#state.streams),
                        next_stream_id = StreamId + 2
                    },

                    {keep_state, State1, [{reply, From, {ok, StreamId}}]}
                    end
            end
    end;

handle_send_request(From, _Method, _Path, _Headers, _EndStream, State) ->
    {keep_state, State, [{reply, From, {error, not_client}}]}.

handle_send_request_headers(From, Headers, EndStream, #state{mode = client, next_stream_id = StreamId,
                                                              peer_max_concurrent_streams = MaxStreams,
                                                              peer_initial_window_size = InitialWindow,
                                                              peer_settings = PeerSettings,
                                                              encode_context = EncCtx} = State) ->
    ActiveStreams = count_active_streams(State),
    case MaxStreams of
        N when is_integer(N), ActiveStreams >= N ->
            {keep_state, State, [{reply, From, {error, max_streams_exceeded}}]};
        _ ->
            Method = proplists:get_value(<<":method">>, Headers),
            Protocol = proplists:get_value(<<":protocol">>, Headers),
            %% RFC 8441: client MUST NOT send Extended CONNECT until peer has
            %% advertised SETTINGS_ENABLE_CONNECT_PROTOCOL=1; method MUST be
            %% CONNECT when `:protocol` is present.
            ExtendedConnectGuard = case Protocol of
                undefined -> ok;
                _ when Method =/= <<"CONNECT">> ->
                    {error, extended_connect_method};
                _ ->
                    case h2_settings:get(enable_connect_protocol, PeerSettings) of
                        1 -> ok;
                        _ -> {error, extended_connect_disabled}
                    end
            end,
            case ExtendedConnectGuard of
                {error, _} = ECErr ->
                    {keep_state, State, [{reply, From, ECErr}]};
                ok ->
            case validate_outbound_request(Headers) of
                {error, _} = Err ->
                    {keep_state, State, [{reply, From, Err}]};
                ok ->
            case check_peer_max_header_list_size(Headers, State) of
                {error, _} = SErr ->
                    {keep_state, State, [{reply, From, SErr}]};
                ok ->
            {HeaderBlock, EncCtx1} = h2_hpack:encode(Headers, EncCtx),
            RecvWindow = h2_settings:get(initial_window_size, State#state.local_settings),
            StreamState = case EndStream of true -> half_closed_local; false -> open end,
            %% RFC 7540 §8.3 / RFC 8441: tunnel only opens on the 2xx response.
            Stream = #stream{
                id = StreamId,
                state = StreamState,
                window_size = InitialWindow,
                recv_window_size = RecvWindow,
                tunnel = false,
                protocol = Protocol,
                request_method = Method
            },
            send_header_block(StreamId, HeaderBlock, EndStream, State),
            State1 = State#state{
                encode_context = EncCtx1,
                streams = maps:put(StreamId, Stream, State#state.streams),
                next_stream_id = StreamId + 2
            },
            {keep_state, State1, [{reply, From, {ok, StreamId}}]}
            end
            end
            end
    end;
handle_send_request_headers(From, _Headers, _EndStream, State) ->
    {keep_state, State, [{reply, From, {error, not_client}}]}.

handle_send_response(From, StreamId, Status, Headers, #state{mode = server, streams = Streams,
                                                              encode_context = EncCtx} = State) ->
    case maps:find(StreamId, Streams) of
        _ when Status =:= 101 ->
            %% RFC 9113 §8.6: HTTP/2 MUST NOT generate 101 Switching Protocols.
            {keep_state, State, [{reply, From, {error, status_101_forbidden}}]};
        {ok, #stream{state = StreamState, request_method = ReqMethod} = Stream}
          when StreamState == open; StreamState == half_closed_remote ->
            %% RFC 7540 §8.3: a CONNECT 2xx response MUST NOT carry
            %% Content-Length or Transfer-Encoding; the stream becomes a
            %% tunnel only when the 2xx goes out, never before.
            IsConnectRequest = ReqMethod =:= <<"CONNECT">>,
            IsSuccess        = Status >= 200 andalso Status < 300,
            case IsConnectRequest andalso IsSuccess andalso
                 has_banned_tunnel_header(Headers) of
                true ->
                    {keep_state, State,
                     [{reply, From, {error, banned_header_in_tunnel_response}}]};
                false ->
                    StatusBin = integer_to_binary(Status),
                    AllHeaders = [{<<":status">>, StatusBin} | Headers],
                    case validate_outbound_response(AllHeaders) of
                        {error, _} = Err ->
                            {keep_state, State, [{reply, From, Err}]};
                        ok ->
                    case check_peer_max_header_list_size(AllHeaders, State) of
                        {error, _} = SErr ->
                            {keep_state, State, [{reply, From, SErr}]};
                        ok ->
                    {HeaderBlock, EncCtx1} = h2_hpack:encode(AllHeaders, EncCtx),
                    send_header_block(StreamId, HeaderBlock, false, State),
                    NewTunnel = IsConnectRequest andalso IsSuccess,
                    Stream1 = Stream#stream{response_headers = AllHeaders, tunnel = NewTunnel},
                    State1 = State#state{
                        encode_context = EncCtx1,
                        streams = maps:put(StreamId, Stream1, Streams)
                    },
                    {keep_state, State1, [{reply, From, ok}]}
                    end
                    end
            end;
        {ok, _} ->
            {keep_state, State, [{reply, From, {error, invalid_stream_state}}]};
        error ->
            {keep_state, State, [{reply, From, {error, unknown_stream}}]}
    end;

handle_send_response(From, _StreamId, _Status, _Headers, State) ->
    {keep_state, State, [{reply, From, {error, not_server}}]}.

%% RFC 9113 §4.2: a HEADERS frame's payload must not exceed
%% SETTINGS_MAX_FRAME_SIZE advertised by the peer. If our encoded block is
%% larger, split it across one HEADERS frame + one or more CONTINUATION
%% frames. No other frames on this stream may interleave.
send_header_block(StreamId, HeaderBlock, EndStream, #state{peer_max_frame_size = MaxFrameSize} = State) ->
    case byte_size(HeaderBlock) =< MaxFrameSize of
        true ->
            send_frame(h2_frame:headers(StreamId, HeaderBlock, EndStream), State);
        false ->
            <<First:MaxFrameSize/binary, Rest/binary>> = HeaderBlock,
            send_frame(h2_frame:headers(StreamId, First, EndStream, false), State),
            send_continuations(StreamId, Rest, MaxFrameSize, State)
    end.

send_continuations(StreamId, Rest, MaxFrameSize, State) when byte_size(Rest) =< MaxFrameSize ->
    send_frame(h2_frame:continuation(StreamId, Rest, true), State);
send_continuations(StreamId, Rest, MaxFrameSize, State) ->
    <<Chunk:MaxFrameSize/binary, More/binary>> = Rest,
    send_frame(h2_frame:continuation(StreamId, Chunk, false), State),
    send_continuations(StreamId, More, MaxFrameSize, State).

%% RFC 7540 §8.3: forbidden on a 2xx CONNECT response.
has_banned_tunnel_header(Headers) ->
    lists:any(fun({Name, _}) ->
        Name =:= <<"content-length">> orelse Name =:= <<"transfer-encoding">>
    end, Headers).

handle_send_data(From, StreamId, Data, EndStream, #state{streams = Streams, conn_window_size = ConnWindow,
                                                          peer_max_frame_size = MaxFrameSize} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{state = StreamState, window_size = StreamWindow, send_buffer = Buffer} = Stream}
          when StreamState == open; StreamState == half_closed_remote ->

            %% Calculate how much we can send
            Available = min(ConnWindow, StreamWindow),
            ToSend = min(Available, byte_size(Data)),
            ToSend1 = min(ToSend, MaxFrameSize),

            case ToSend1 of
                0 when byte_size(Data) > 0 ->
                    %% Need to buffer - also track if EndStream should be set when flushing
                    NewBuffer = <<Buffer/binary, Data/binary>>,
                    Stream1 = Stream#stream{send_buffer = NewBuffer, pending_end_stream = EndStream},
                    State1 = State#state{streams = maps:put(StreamId, Stream1, Streams)},
                    {keep_state, State1, [{reply, From, ok}]};

                _ ->
                    %% Send what we can
                    <<SendData:ToSend1/binary, Remaining/binary>> = Data,
                    IsEnd = EndStream andalso Remaining == <<>> andalso Buffer == <<>>,
                    Frame = h2_frame:data(StreamId, SendData, IsEnd),
                    send_frame(Frame, State),

                    %% Update windows
                    NewConnWindow = ConnWindow - ToSend1,
                    NewStreamWindow = StreamWindow - ToSend1,

                    %% Update stream state; Remaining is handled via recursion below,
                    %% so it must not be appended to send_buffer (would cause duplication).
                    Stream1 = Stream#stream{
                        window_size = NewStreamWindow,
                        send_buffer = Buffer,
                        pending_end_stream = EndStream andalso Remaining =/= <<>>,
                        state = case IsEnd of
                            true ->
                                case StreamState of
                                    open -> half_closed_local;
                                    half_closed_remote -> closed
                                end;
                            false ->
                                StreamState
                        end
                    },

                    State1 = State#state{
                        conn_window_size = NewConnWindow,
                        streams = maps:put(StreamId, Stream1, Streams)
                    },

                    %% If there's more data, try to send it
                    case Remaining of
                        <<>> ->
                            {keep_state, State1, [{reply, From, ok}]};
                        _ ->
                            handle_send_data(From, StreamId, Remaining, EndStream, State1)
                    end
            end;
        {ok, _} ->
            {keep_state, State, [{reply, From, {error, invalid_stream_state}}]};
        error ->
            {keep_state, State, [{reply, From, {error, unknown_stream}}]}
    end.

handle_send_trailers(From, StreamId, Trailers, #state{streams = Streams, encode_context = EncCtx} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{tunnel = true}} ->
            %% RFC 7540 §8.3: trailers are forbidden on a CONNECT tunnel.
            {keep_state, State, [{reply, From, {error, tunnel_no_trailers}}]};
        {ok, #stream{state = StreamState} = Stream} when StreamState == open; StreamState == half_closed_remote ->
            case validate_trailers(Trailers, true) of
                {error, _} = Err ->
                    {keep_state, State, [{reply, From, Err}]};
                ok ->
            case check_peer_max_header_list_size(Trailers, State) of
                {error, _} = SErr ->
                    {keep_state, State, [{reply, From, SErr}]};
                ok ->
            %% Encode trailers
            {HeaderBlock, EncCtx1} = h2_hpack:encode(Trailers, EncCtx),

            %% Send HEADERS frame with END_STREAM
            send_header_block(StreamId, HeaderBlock, true, State),

            %% Update stream state
            Stream1 = Stream#stream{
                state = case StreamState of
                    open -> half_closed_local;
                    half_closed_remote -> closed
                end
            },

            State1 = State#state{
                encode_context = EncCtx1,
                streams = maps:put(StreamId, Stream1, Streams)
            },

            case Stream1#stream.state of
                closed ->
                    State2 = close_stream(StreamId, State1),
                    {keep_state, State2, [{reply, From, ok}]};
                _ ->
                    {keep_state, State1, [{reply, From, ok}]}
            end
            end
            end;
        {ok, _} ->
            {keep_state, State, [{reply, From, {error, invalid_stream_state}}]};
        error ->
            {keep_state, State, [{reply, From, {error, unknown_stream}}]}
    end.

handle_cancel_stream(From, StreamId, ErrorCode, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{state = StreamState}} when StreamState =/= closed ->
            send_rst_stream(StreamId, ErrorCode, State),
            State1 = close_stream(StreamId, State),
            {keep_state, State1, [{reply, From, ok}]};
        {ok, _} ->
            {keep_state, State, [{reply, From, {error, stream_closed}}]};
        error ->
            {keep_state, State, [{reply, From, {error, unknown_stream}}]}
    end.

handle_set_stream_handler(From, StreamId, Pid, Opts, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{recv_buffer = Buf} = Stream} ->
            Drain = maps:get(drain_buffer, Opts, true),
            Stream1 = Stream#stream{handler = Pid, recv_buffer = []},
            State1 = put_stream(StreamId, Stream1, State),
            Reply = case {Drain, Buf} of
                {true, []}      -> ok;
                {true, _}       -> {ok, lists:reverse(Buf)};
                {false, _} ->
                    %% Re-send buffered data as messages to the handler.
                    lists:foreach(fun({D, Fin}) ->
                        Pid ! {h2, self(), {data, StreamId, D, Fin}},
                        ok
                    end, lists:reverse(Buf)),
                    ok
            end,
            {keep_state, State1, [{reply, From, Reply}]};
        error ->
            {keep_state, State, [{reply, From, {error, unknown_stream}}]}
    end.

handle_unset_stream_handler(From, StreamId, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, Stream} ->
            Stream1 = Stream#stream{handler = undefined},
            State1 = put_stream(StreamId, Stream1, State),
            {keep_state, State1, [{reply, From, ok}]};
        error ->
            {keep_state, State, [{reply, From, ok}]}
    end.

%% Deliver DATA to the stream's registered handler, or fall back to the
%% mode default (client→owner, server→buffer for later handler).
%% Matches quic_h3:notify_stream_data/4 semantics.
dispatch_data(StreamId, #stream{handler = Pid} = Stream, Data, Fin, State) when is_pid(Pid) ->
    _ = Pid ! {h2, self(), {data, StreamId, Data, Fin}},
    {Stream, State};
dispatch_data(StreamId, #stream{} = Stream, Data, Fin, #state{mode = client} = State) ->
    notify_owner({h2, self(), {data, StreamId, Data, Fin}}, State),
    {Stream, State};
dispatch_data(_StreamId, #stream{recv_buffer = Buf} = Stream, Data, Fin, State) ->
    {Stream#stream{recv_buffer = [{Data, Fin} | Buf]}, State}.

handle_send_goaway(From, ErrorCode, _CurrentState, State) ->
    %% RFC 7540 §6.8: two-phase GOAWAY. Send a "shutdown warning" first with
    %% LastStreamID = 2^31-1 and NO_ERROR so the peer can finish in-flight
    %% streams; after a brief drain, send the real GOAWAY with the actual
    %% last_peer_stream_id and close.
    State1 = send_goaway_frame(?MAX_STREAM_ID, no_error, State),
    notify_owner({h2, self(), goaway_sent}, State1),
    DrainTimer = erlang:start_timer(?GOAWAY_DRAIN_MS, self(), goaway_drain),
    State2 = State1#state{
        goaway_error = ErrorCode,
        close_timer = DrainTimer
    },
    {next_state, goaway_sent, State2, [{reply, From, ok}]}.

%% ============================================================================
%% Internal: Common Call Handling
%% ============================================================================

handle_call_early(From, Request, StateName, #state{waiters = Waiters} = State) ->
    case Request of
        wait_connected ->
            %% Queue this caller to be notified when connected
            {keep_state, State#state{waiters = [From | Waiters]}};
        get_settings ->
            {keep_state, State, [{reply, From, State#state.local_settings}]};
        get_peer_settings ->
            {keep_state, State, [{reply, From, State#state.peer_settings}]};
        {controlling_process, NewOwner} ->
            {keep_state, State#state{owner = NewOwner}, [{reply, From, ok}]};
        _ ->
            {keep_state, State, [{reply, From, {error, {not_ready, StateName}}}]}
    end.

handle_call_common(From, Request, _StateName, State) ->
    case Request of
        get_settings ->
            {keep_state, State, [{reply, From, State#state.local_settings}]};
        get_peer_settings ->
            {keep_state, State, [{reply, From, State#state.peer_settings}]};
        {controlling_process, NewOwner} ->
            {keep_state, State#state{owner = NewOwner}, [{reply, From, ok}]};
        _ ->
            {keep_state, State, [{reply, From, {error, unknown_request}}]}
    end.

handle_common(info, {'EXIT', Owner, Reason}, _StateName, #state{owner = Owner} = State) ->
    {stop, {shutdown, {owner_exit, Reason}}, State};
handle_common(info, {tcp_error, Socket, Reason}, _StateName, #state{socket = Socket} = State) ->
    {stop, {shutdown, {tcp_error, Reason}}, State};
handle_common(info, {ssl_error, Socket, Reason}, _StateName, #state{socket = Socket} = State) ->
    {stop, {shutdown, {ssl_error, Reason}}, State};
handle_common(_EventType, _Event, _StateName, State) ->
    {keep_state, State}.

%% ============================================================================
%% Internal: Stream Management
%% ============================================================================

validate_stream_id(StreamId, client, #state{last_peer_stream_id = LastPeer}) ->
    %% Server-initiated streams must be even
    if
        StreamId rem 2 == 1 -> {error, protocol_error};  % Must be even
        StreamId =< LastPeer -> {error, protocol_error};  % Must be new
        true -> ok
    end;
validate_stream_id(StreamId, server, #state{last_peer_stream_id = LastPeer}) ->
    %% Client-initiated streams must be odd
    if
        StreamId rem 2 == 0 -> {error, protocol_error};  % Must be odd
        StreamId =< LastPeer -> {error, protocol_error};  % Must be new
        true -> ok
    end.

get_or_create_stream(StreamId, #state{streams = Streams,
                                       peer_initial_window_size = InitialWindow,
                                       local_settings = LocalSettings} = _State) ->
    case maps:find(StreamId, Streams) of
        {ok, Stream} ->
            Stream;
        error ->
            RecvWindow = h2_settings:get(initial_window_size, LocalSettings),
            #stream{
                id = StreamId,
                state = idle,
                window_size = InitialWindow,
                recv_window_size = RecvWindow
            }
    end.

put_stream(StreamId, Stream, #state{streams = Streams} = State) ->
    State#state{streams = maps:put(StreamId, Stream, Streams)}.

close_stream(StreamId, #state{streams = Streams} = State) ->
    State#state{streams = maps:remove(StreamId, Streams)}.

count_active_streams(#state{streams = Streams}) ->
    maps:fold(fun(_Id, #stream{state = S}, Acc) ->
        case S of
            closed -> Acc;
            _ -> Acc + 1
        end
    end, 0, Streams).

flush_send_buffers(#state{streams = Streams} = State) ->
    maps:fold(fun(StreamId, _Stream, AccState) ->
        flush_stream_buffer(StreamId, AccState)
    end, State, Streams).

flush_stream_buffer(StreamId, #state{streams = Streams, conn_window_size = ConnWindow,
                                      peer_max_frame_size = MaxFrameSize} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{send_buffer = <<>>}} ->
            State;
        {ok, #stream{send_buffer = Buffer, window_size = StreamWindow,
                     pending_end_stream = PendingEnd, state = StreamState} = Stream} ->
            Available = min(ConnWindow, StreamWindow),
            ToSend = min(Available, byte_size(Buffer)),
            ToSend1 = min(ToSend, MaxFrameSize),

            case ToSend1 of
                0 ->
                    State;
                _ ->
                    <<SendData:ToSend1/binary, Remaining/binary>> = Buffer,
                    IsEnd = PendingEnd andalso Remaining == <<>>,
                    Frame = h2_frame:data(StreamId, SendData, IsEnd),
                    send_frame(Frame, State),

                    NewStreamState = case IsEnd of
                        true ->
                            case StreamState of
                                open -> half_closed_local;
                                half_closed_remote -> closed;
                                _ -> StreamState
                            end;
                        false ->
                            StreamState
                    end,

                    Stream1 = Stream#stream{
                        send_buffer = Remaining,
                        window_size = StreamWindow - ToSend1,
                        pending_end_stream = PendingEnd andalso Remaining =/= <<>>,
                        state = NewStreamState
                    },
                    State1 = State#state{
                        conn_window_size = ConnWindow - ToSend1,
                        streams = maps:put(StreamId, Stream1, Streams)
                    },

                    %% Try to send more
                    flush_stream_buffer(StreamId, State1)
            end;
        error ->
            State
    end.

%% ============================================================================
%% Internal: Frame Sending
%% ============================================================================

send_preface(#state{socket = Socket, transport = Transport} = State) ->
    %% Send connection preface (tolerate peer-close mid-send)
    _ = Transport:send(Socket, ?H2_PREFACE),
    send_settings_frame(State).

send_settings_frame(#state{local_settings = Settings, pending_settings = Pending} = State) ->
    Frame = h2_frame:settings(settings_to_list(Settings)),
    send_frame(Frame, State),
    State#state{pending_settings = Pending ++ [Settings]}.

settings_to_list(Settings) ->
    maps:fold(fun(Key, Value, Acc) ->
        case setting_id(Key) of
            undefined -> Acc;
            Id -> [{Id, encode_setting_value(Value)} | Acc]
        end
    end, [], Settings).

setting_id(header_table_size) -> 16#1;
setting_id(enable_push) -> 16#2;
setting_id(max_concurrent_streams) -> 16#3;
setting_id(initial_window_size) -> 16#4;
setting_id(max_frame_size) -> 16#5;
setting_id(max_header_list_size) -> 16#6;
setting_id(enable_connect_protocol) -> 16#8;
setting_id(_) -> undefined.

encode_setting_value(unlimited) -> 16#ffffffff;
encode_setting_value(V) -> V.

send_frame(Frame, #state{socket = Socket, transport = Transport}) ->
    Bin = h2_frame:encode(Frame),
    case Transport:send(Socket, Bin) of
        ok -> ok;
        {error, _Reason} -> ok  %% Peer closed; let subsequent handling clean up
    end.

send_goaway_frame(LastStreamId, ErrorCode, #state{socket = Socket, transport = Transport} = State) ->
    Frame = h2_frame:goaway(LastStreamId, ErrorCode, <<>>),
    Bin = h2_frame:encode(Frame),
    _ = Transport:send(Socket, Bin),
    State#state{goaway_sent = true, goaway_error = ErrorCode}.

send_rst_stream(StreamId, ErrorCode, #state{socket = Socket, transport = Transport}) ->
    Frame = h2_frame:rst_stream(StreamId, ErrorCode),
    Bin = h2_frame:encode(Frame),
    _ = Transport:send(Socket, Bin),
    ok.

%% ============================================================================
%% Internal: Utilities
%% ============================================================================

set_active(gen_tcp, Socket) ->
    inet:setopts(Socket, [{active, once}]);
set_active(ssl, Socket) ->
    ssl:setopts(Socket, [{active, once}]).

%% Stop the gen_statem with Reason, replying {error, Reason} to any waiters
%% that called wait_connected before we reached the connected state.
stop_and_notify_waiters(Reason, #state{waiters = Waiters} = State) ->
    Replies = [{reply, From, {error, peel_reason(Reason)}} || From <- Waiters],
    {stop_and_reply, Reason, Replies, State#state{waiters = []}}.

peel_reason({shutdown, R}) -> R;
peel_reason(R) -> R.

is_ssl_socket(Socket) when is_tuple(Socket) ->
    element(1, Socket) =:= sslsocket;
is_ssl_socket(_) ->
    false.

notify_owner(Msg, #state{owner = Owner}) ->
    Owner ! Msg,
    ok.

%% Send a per-stream event to the registered stream handler if any, else
%% fall back to the connection owner. Used for stream_reset and trailers so
%% they follow the same routing as DATA dispatched via dispatch_data/5.
notify_stream(StreamId, Event, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{handler = Pid}} when is_pid(Pid) ->
            Pid ! {h2, self(), Event},
            ok;
        _ ->
            notify_owner({h2, self(), Event}, State)
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

parse_status_test_() ->
    [?_assertEqual({ok, 200}, parse_status([{<<":status">>, <<"200">>}])),
     ?_assertEqual({ok, 100}, parse_status([{<<":status">>, <<"100">>}])),
     ?_assertEqual({ok, 599}, parse_status([{<<":status">>, <<"599">>}])),
     ?_assertEqual(malformed, parse_status([{<<":status">>, <<"abc">>}])),
     ?_assertEqual(malformed, parse_status([{<<":status">>, <<"2000">>}])),
     ?_assertEqual(malformed, parse_status([{<<":status">>, <<"99">>}])),
     ?_assertEqual(malformed, parse_status([{<<":status">>, <<"600">>}])),
     ?_assertEqual(malformed, parse_status([{<<":status">>, <<>>}])),
     ?_assertEqual(malformed, parse_status([]))].

parse_content_length_test_() ->
    [?_assertEqual({ok, undefined}, parse_content_length([])),
     ?_assertEqual({ok, 0},  parse_content_length([{<<"content-length">>, <<"0">>}])),
     ?_assertEqual({ok, 42}, parse_content_length([{<<"content-length">>, <<"42">>}])),
     %% Duplicate with same value collapses.
     ?_assertEqual({ok, 42}, parse_content_length([{<<"content-length">>, <<"42">>},
                                                    {<<"content-length">>, <<"42">>}])),
     %% Mismatched duplicates → malformed.
     ?_assertEqual({error, protocol_error},
                   parse_content_length([{<<"content-length">>, <<"1">>},
                                         {<<"content-length">>, <<"2">>}])),
     %% Non-numeric.
     ?_assertEqual({error, protocol_error},
                   parse_content_length([{<<"content-length">>, <<"abc">>}])),
     %% Negative.
     ?_assertEqual({error, protocol_error},
                   parse_content_length([{<<"content-length">>, <<"-1">>}]))].

header_value_validation_test_() ->
    [?_assertEqual({error, protocol_error},
                   check_lowercase_names([{<<"x">>, <<"a", 0, "b">>}])),
     ?_assertEqual({error, protocol_error},
                   check_lowercase_names([{<<"x">>, <<"a\nb">>}])),
     ?_assertEqual({error, protocol_error},
                   check_lowercase_names([{<<"x">>, <<"a\rb">>}])),
     ?_assertEqual({error, protocol_error},
                   check_lowercase_names([{<<>>, <<"v">>}])),
     ?_assertEqual(ok,
                   check_lowercase_names([{<<"x">>, <<"ok">>}]))].
-endif.
