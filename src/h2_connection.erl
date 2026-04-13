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
    tunnel = false :: boolean()
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
    scheme = <<"https">> :: binary()
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
    LocalSettings = (maps:merge(h2_settings:default(), UserSettings))#{enable_push => 0},
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
        scheme = Scheme
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

handle_frame(StateName, {goaway, LastStreamId, _ErrorCode, _DebugData}, State) ->
    notify_owner({h2, self(), {goaway, LastStreamId}}, State),
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
            notify_owner({h2, self(), {stream_reset, StreamId, h2_error:name(ErrorCode)}}, State),
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
            %% Determine whether this is an initial HEADERS (request/response)
            %% or a trailing HEADERS. Only initial HEADERS carry pseudo-headers
            %% (RFC 7540 §8.1.2.3 / §8.1.2.4). Trailers have their own rules
            %% (§8.1: MUST have END_STREAM, MUST NOT carry pseudo-headers).
            IsInitialHeaders = case Mode of
                server -> true;
                client ->
                    case maps:find(StreamId, State1#state.streams) of
                        {ok, #stream{response_headers = []}} -> true;
                        error -> true;
                        _ -> false
                    end
            end,
            %% RFC 7540 §8.3: HEADERS (trailers) are not allowed on a CONNECT
            %% tunnel — reject as stream PROTOCOL_ERROR.
            IsTunnel = case maps:find(StreamId, State1#state.streams) of
                {ok, #stream{tunnel = T}} -> T;
                _ -> false
            end,
            Validation = case {IsInitialHeaders, IsTunnel} of
                {true, _}     -> validate_initial_headers(Mode, Headers);
                {false, true} -> {error, protocol_error};
                {false, false} -> validate_trailers(Headers, EndStream)
            end,
            case Validation of
                ok ->
                    decode_and_process_headers_cont(StreamId, Headers, EndStream, State1);
                {error, ValidErr} ->
                    send_rst_stream(StreamId, ValidErr, State1),
                    State2 = case maps:is_key(StreamId, State1#state.streams) of
                        true -> close_stream(StreamId, State1);
                        false -> State1
                    end,
                    {ok, connected, State2}
            end;
        {error, Reason} ->
            error_logger:error_msg("HPACK decode error: ~p~n", [Reason]),
            {error, compression_error, State}
    end.

decode_and_process_headers_cont(StreamId, Headers, EndStream, #state{mode = Mode} = State1) ->
    Stream = get_or_create_stream(StreamId, State1),
    case Mode of
        server ->
                    %% This is a request
                    {Method, Path, OtherHeaders} = extract_request_headers(Headers),
                    IsTunnel = Method =:= <<"CONNECT">>,
                    %% RFC 7540 §8.3: CONNECT streams stay "open" even when
                    %% the client never sends END_STREAM with the HEADERS;
                    %% we still honour END_STREAM-on-headers (uncommon for
                    %% CONNECT) but mark the stream as a tunnel candidate.
                    Stream1 = Stream#stream{
                        state = case EndStream of true -> half_closed_remote; false -> open end,
                        request_headers = Headers,
                        tunnel = IsTunnel
                    },
                    State2 = put_stream(StreamId, Stream1, State1),
                    State3 = State2#state{last_peer_stream_id = max(StreamId, State2#state.last_peer_stream_id)},

                    notify_owner({h2, self(), {request, StreamId, Method, Path, OtherHeaders}}, State3),
                    {ok, connected, State3};

                client ->
                    %% Check if this is a response or trailers
                    case Stream#stream.response_headers of
                        [] ->
                            %% RFC 9113 §8.3.2: :status must be a 3-digit
                            %% integer in 100..599. A malformed value is a
                            %% stream-level PROTOCOL_ERROR, not a crash.
                            case parse_status(Headers) of
                                {ok, Status} ->
                                    Stream1 = Stream#stream{
                                        state = case EndStream of true -> half_closed_remote; false -> open end,
                                        response_headers = Headers
                                    },
                                    State2 = put_stream(StreamId, Stream1, State1),
                                    OtherHeaders = lists:filter(fun({N, _}) -> not is_pseudo_header(N) end, Headers),
                                    notify_owner({h2, self(), {response, StreamId, Status, OtherHeaders}}, State2),
                                    case EndStream of
                                        true ->
                                            State3 = close_stream(StreamId, State2),
                                            {ok, connected, State3};
                                        false ->
                                            {ok, connected, State2}
                                    end;
                                malformed ->
                                    send_rst_stream(StreamId, protocol_error, State1),
                                    State2 = close_stream(StreamId, State1),
                                    {ok, connected, State2}
                            end;
                        _ ->
                            %% This is trailers (subsequent HEADERS on this stream)
                            Stream1 = Stream#stream{state = closed},
                            State2 = put_stream(StreamId, Stream1, State1),

                            %% Notify owner with trailers
                            notify_owner({h2, self(), {trailers, StreamId, Headers}}, State2),

                            State3 = close_stream(StreamId, State2),
                            {ok, connected, State3}
                    end
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

check_lowercase_names(Headers) ->
    %% Pseudo-header names already start with ':' and by convention are
    %% lowercase; we only need to verify the ASCII letters in each name byte.
    HasUpper = lists:any(fun({Name, _}) -> has_upper(Name) end, Headers),
    case HasUpper of
        true -> {error, protocol_error};
        false -> ok
    end.

has_upper(<<>>) -> false;
has_upper(<<C, _/binary>>) when C >= $A, C =< $Z -> true;
has_upper(<<_, Rest/binary>>) -> has_upper(Rest).

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
        <<"CONNECT">> -> ok;  %% CONNECT has no :path/:scheme
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
            case proplists:get_value(<<"host">>, Headers) of
                undefined -> ok;
                Host ->
                    case string:equal(Authority, Host, true) of
                        true -> ok;
                        false -> {error, protocol_error}
                    end
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
            Allowed = [<<":method">>, <<":scheme">>, <<":path">>, <<":authority">>],
            case [N || N <- Pseudos, not lists:member(N, Allowed)] of
                [] ->
                    Method = proplists:get_value(<<":method">>, Headers),
                    case Method of
                        undefined -> {error, protocol_error};
                        <<"CONNECT">> ->
                            case proplists:get_value(<<":authority">>, Headers) of
                                undefined -> {error, protocol_error};
                                _ -> ok
                            end;
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
    OtherHeaders = lists:filter(fun({N, _}) -> not is_pseudo_header(N) end, Headers),
    {Method, Path, OtherHeaders}.

%% RFC 9113 §8.3.2: :status MUST be present on a response HEADERS, exactly
%% three ASCII digits in the range 100..599. Anything else is a malformed
%% response and must trigger a stream PROTOCOL_ERROR.
parse_status(Headers) ->
    case proplists:get_value(<<":status">>, Headers) of
        <<D1, D2, D3>> when D1 >= $1, D1 =< $5, D2 >= $0, D2 =< $9, D3 >= $0, D3 =< $9 ->
            {ok, (D1 - $0) * 100 + (D2 - $0) * 10 + (D3 - $0)};
        _ ->
            malformed
    end.

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
                {ok, #stream{state = StreamState, recv_window_size = StreamWindow} = Stream} when StreamState == open; StreamState == half_closed_local ->
                    if
                        FlowControlled > StreamWindow ->
                            send_rst_stream(StreamId, flow_control_error, State0a),
                            State1 = close_stream(StreamId, State0a),
                            {ok, connected, State1};
                        true ->
                            NewStreamWindow = StreamWindow - FlowControlled,
                            Stream1 = Stream#stream{recv_window_size = NewStreamWindow},

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

            {HeaderBlock, EncCtx1} = h2_hpack:encode(AllHeaders, EncCtx),

            RecvWindow = h2_settings:get(initial_window_size, State#state.local_settings),
            StreamState = case EndStream of
                true -> half_closed_local;
                false -> open
            end,
            Stream = #stream{
                id = StreamId,
                state = StreamState,
                window_size = InitialWindow,
                recv_window_size = RecvWindow,
                tunnel = IsConnect
            },

            Frame = h2_frame:headers(StreamId, HeaderBlock, EndStream),
            send_frame(Frame, State),

            State1 = State#state{
                encode_context = EncCtx1,
                streams = maps:put(StreamId, Stream, State#state.streams),
                next_stream_id = StreamId + 2
            },

            {keep_state, State1, [{reply, From, {ok, StreamId}}]}
    end;

handle_send_request(From, _Method, _Path, _Headers, _EndStream, State) ->
    {keep_state, State, [{reply, From, {error, not_client}}]}.

handle_send_request_headers(From, Headers, EndStream, #state{mode = client, next_stream_id = StreamId,
                                                              peer_max_concurrent_streams = MaxStreams,
                                                              peer_initial_window_size = InitialWindow,
                                                              encode_context = EncCtx} = State) ->
    ActiveStreams = count_active_streams(State),
    case MaxStreams of
        N when is_integer(N), ActiveStreams >= N ->
            {keep_state, State, [{reply, From, {error, max_streams_exceeded}}]};
        _ ->
            IsConnect = proplists:get_value(<<":method">>, Headers) =:= <<"CONNECT">>,
            {HeaderBlock, EncCtx1} = h2_hpack:encode(Headers, EncCtx),
            RecvWindow = h2_settings:get(initial_window_size, State#state.local_settings),
            StreamState = case EndStream of true -> half_closed_local; false -> open end,
            Stream = #stream{
                id = StreamId,
                state = StreamState,
                window_size = InitialWindow,
                recv_window_size = RecvWindow,
                tunnel = IsConnect
            },
            Frame = h2_frame:headers(StreamId, HeaderBlock, EndStream),
            send_frame(Frame, State),
            State1 = State#state{
                encode_context = EncCtx1,
                streams = maps:put(StreamId, Stream, State#state.streams),
                next_stream_id = StreamId + 2
            },
            {keep_state, State1, [{reply, From, {ok, StreamId}}]}
    end;
handle_send_request_headers(From, _Headers, _EndStream, State) ->
    {keep_state, State, [{reply, From, {error, not_client}}]}.

handle_send_response(From, StreamId, Status, Headers, #state{mode = server, streams = Streams,
                                                              encode_context = EncCtx} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{state = StreamState, tunnel = IsTunnel} = Stream}
          when StreamState == open; StreamState == half_closed_remote ->
            %% RFC 7540 §8.3: a tunnel response (CONNECT 2xx) MUST NOT carry
            %% Content-Length or Transfer-Encoding headers.
            case IsTunnel andalso Status >= 200 andalso Status < 300 andalso
                 has_banned_tunnel_header(Headers) of
                true ->
                    {keep_state, State,
                     [{reply, From, {error, banned_header_in_tunnel_response}}]};
                false ->
                    StatusBin = integer_to_binary(Status),
                    AllHeaders = [{<<":status">>, StatusBin} | Headers],
                    {HeaderBlock, EncCtx1} = h2_hpack:encode(AllHeaders, EncCtx),
                    Frame = h2_frame:headers(StreamId, HeaderBlock, false),
                    send_frame(Frame, State),
                    %% Tunnel is "established" once a 2xx response goes out;
                    %% non-2xx responses keep tunnel=false (and the stream
                    %% behaves like a normal short response).
                    NewTunnel = IsTunnel andalso Status >= 200 andalso Status < 300,
                    Stream1 = Stream#stream{response_headers = AllHeaders, tunnel = NewTunnel},
                    State1 = State#state{
                        encode_context = EncCtx1,
                        streams = maps:put(StreamId, Stream1, Streams)
                    },
                    {keep_state, State1, [{reply, From, ok}]}
            end;
        {ok, _} ->
            {keep_state, State, [{reply, From, {error, invalid_stream_state}}]};
        error ->
            {keep_state, State, [{reply, From, {error, unknown_stream}}]}
    end;

handle_send_response(From, _StreamId, _Status, _Headers, State) ->
    {keep_state, State, [{reply, From, {error, not_server}}]}.

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
            %% Encode trailers
            {HeaderBlock, EncCtx1} = h2_hpack:encode(Trailers, EncCtx),

            %% Send HEADERS frame with END_STREAM
            Frame = h2_frame:headers(StreamId, HeaderBlock, true),
            send_frame(Frame, State),

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
-endif.
