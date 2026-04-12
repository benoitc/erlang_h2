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

%% Stream states per RFC 7540 Section 5.1
-record(stream, {
    id :: non_neg_integer(),
    state = idle :: idle | open | half_closed_local | half_closed_remote | closed | reserved_local | reserved_remote,
    window_size :: integer(),
    recv_window_size :: integer(),
    send_buffer = <<>> :: binary(),
    pending_end_stream = false :: boolean(),  %% Track if buffered data should end stream
    header_buffer = <<>> :: binary(),
    request_headers = [] :: [{binary(), binary()}],
    response_headers = [] :: [{binary(), binary()}]
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
    waiters = [] :: [gen_statem:from()]
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
-spec activate(pid()) -> ok.
activate(Conn) ->
    gen_statem:cast(Conn, activate).

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

    %% Initialize settings
    LocalSettings = maps:merge(h2_settings:default(), maps:get(settings, Opts, #{})),
    PeerSettings = h2_settings:default(),

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
        encode_context = EncodeCtx,
        decode_context = DecodeCtx,
        next_stream_id = case Mode of client -> 1; server -> 2 end,
        conn_window_size = InitialWindow,
        recv_conn_window_size = RecvWindow
    },

    %% Note: Socket is NOT set to active here - it will be activated
    %% in the preface state after socket ownership is properly transferred.
    %% The caller must transfer socket ownership before the connection can receive data.

    {ok, preface, State}.

terminate(_Reason, _StateName, #state{socket = Socket, transport = Transport, goaway_sent = GoawaySent}) ->
    %% Send GOAWAY if not already sent
    case GoawaySent of
        false ->
            Frame = h2_frame:goaway(0, no_error, <<>>),
            _ = Transport:send(Socket, h2_frame:encode(Frame)),
            ok;
        true ->
            ok
    end,
    Transport:close(Socket),
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

preface(cast, activate, #state{mode = Mode, transport = Transport, socket = Socket} = State) ->
    %% Socket ownership has been transferred, now we can send and receive
    case set_active(Transport, Socket) of
        ok ->
            %% Send connection preface/settings
            State1 = case Mode of
                client ->
                    %% Client sends preface + SETTINGS
                    send_preface(State);
                server ->
                    %% Server just sends SETTINGS
                    send_settings_frame(State)
            end,
            %% Start settings timer
            Timer = erlang:start_timer(?SETTINGS_TIMEOUT_MS, self(), settings_timeout),
            {keep_state, State1#state{settings_timer = Timer}};
        {error, Reason} ->
            stop_and_notify_waiters({shutdown, {socket_error, Reason}}, State)
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

settings(cast, activate, #state{transport = Transport, socket = Socket} = State) ->
    %% Socket ownership has been transferred, set to active mode
    ok = set_active(Transport, Socket),
    {keep_state, State};

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
        _ -> erlang:cancel_timer(Timer)
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
    notify_owner({h2, self(), closed}, State),
    {stop, {shutdown, tcp_closed}, State};
connected(info, {ssl_closed, Socket}, #state{socket = Socket} = State) ->
    notify_owner({h2, self(), closed}, State),
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

goaway_sent(enter, _OldState, State) ->
    %% Start close timer
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

goaway_sent(info, {timeout, Timer, close_timeout}, #state{close_timer = Timer} = State) ->
    {stop, {shutdown, close_timeout}, State};

goaway_sent({call, From}, {send_data, StreamId, Data, EndStream}, State) ->
    %% Allow completing existing streams
    handle_send_data(From, StreamId, Data, EndStream, State);

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
    %% Convert iolist to binary if needed
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

process_frames(StateName, #state{buffer = Buffer} = State) ->
    case h2_frame:decode(Buffer) of
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

handle_frame(StateName, {goaway, LastStreamId, ErrorCode, _DebugData}, State) ->
    notify_owner({h2, self(), {goaway, LastStreamId, h2_error:name(ErrorCode)}}, State),
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

handle_frame(_StateName, {data, StreamId, Data, EndStream}, State) ->
    handle_data_frame(StreamId, Data, EndStream, State);

handle_frame(_StateName, {rst_stream, StreamId, ErrorCode}, State) ->
    notify_owner({h2, self(), {stream_reset, StreamId, h2_error:name(ErrorCode)}}, State),
    State1 = close_stream(StreamId, State),
    {ok, connected, State1};

handle_frame(_StateName, {priority, _StreamId, _Exclusive, _DependsOn, _Weight}, State) ->
    %% Priority is advisory, ignore
    {ok, connected, State};

handle_frame(_StateName, {push_promise, _StreamId, _PromisedId, _HeaderBlock, _EndHeaders}, State) ->
    %% We don't support server push, send GOAWAY
    {error, protocol_error, State};

handle_frame(_StateName, {unknown_frame, _Type, _Flags, _StreamId, _Payload}, State) ->
    %% Ignore unknown frame types per RFC 7540
    {ok, connected, State}.

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
                    State1 = apply_peer_settings(MergedSettings, State),
                    %% Send ACK
                    send_frame(h2_frame:settings_ack(), State1),
                    NewStateName = case State1#state.settings_acked of
                        true -> connected;
                        false -> settings
                    end,
                    {ok, NewStateName, State1};
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
    %% Update HPACK encoder table size
    NewTableSize = h2_settings:get(header_table_size, Settings),
    EncCtx1 = h2_hpack:set_max_table_size(NewTableSize, EncCtx),

    %% Update stream windows if INITIAL_WINDOW_SIZE changed
    OldWindow = h2_settings:get(initial_window_size, OldSettings),
    NewWindow = h2_settings:get(initial_window_size, Settings),
    Delta = NewWindow - OldWindow,
    Streams1 = maps:map(fun(_Id, #stream{window_size = W} = S) ->
        S#stream{window_size = W + Delta}
    end, Streams),

    State#state{
        peer_settings = Settings,
        encode_context = EncCtx1,
        streams = Streams1
    }.

apply_local_settings(Settings, #state{decode_context = DecCtx} = State) ->
    %% Update HPACK decoder table size
    NewTableSize = h2_settings:get(header_table_size, Settings),
    DecCtx1 = h2_hpack:set_max_table_size(NewTableSize, DecCtx),
    State#state{
        local_settings = Settings,
        decode_context = DecCtx1
    }.

%% ============================================================================
%% Internal: Headers Handling
%% ============================================================================

handle_headers(StreamId, HeaderBlock, EndStream, EndHeaders, _Priority, #state{mode = Mode, streams = Streams} = State) ->
    %% Check if this is a response on an existing stream or a new stream
    case maps:find(StreamId, Streams) of
        {ok, _Stream} ->
            %% Existing stream - this is a response (client) or trailers
            case EndHeaders of
                true ->
                    decode_and_process_headers(StreamId, HeaderBlock, EndStream, State);
                false ->
                    Stream = maps:get(StreamId, Streams),
                    Stream1 = Stream#stream{header_buffer = HeaderBlock},
                    State1 = put_stream(StreamId, Stream1, State),
                    {ok, connected, State1}
            end;
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
                            {ok, connected, State1}
                    end;
                {error, ErrorCode} ->
                    {error, ErrorCode, State}
            end
    end.

handle_continuation(StreamId, HeaderBlock, EndHeaders, #state{streams = Streams} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{header_buffer = Buffer} = Stream} ->
            NewBuffer = <<Buffer/binary, HeaderBlock/binary>>,
            case EndHeaders of
                true ->
                    Stream1 = Stream#stream{header_buffer = <<>>},
                    State1 = put_stream(StreamId, Stream1, State),
                    decode_and_process_headers(StreamId, NewBuffer, false, State1);
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
            %% or a trailing HEADERS. Only initial HEADERS are subject to
            %% pseudo-header validation (RFC 7540 §8.1.2.3 / §8.1.2.1).
            IsInitialHeaders = case Mode of
                server -> true;
                client ->
                    case maps:find(StreamId, State1#state.streams) of
                        {ok, #stream{response_headers = []}} -> true;
                        error -> true;
                        _ -> false
                    end
            end,
            case IsInitialHeaders andalso validate_pseudo_headers(Mode, Headers) of
                false ->
                    decode_and_process_headers_cont(StreamId, Headers, EndStream, State1);
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
                    Stream1 = Stream#stream{
                        state = case EndStream of true -> half_closed_remote; false -> open end,
                        request_headers = Headers
                    },
                    State2 = put_stream(StreamId, Stream1, State1),
                    State3 = State2#state{last_peer_stream_id = max(StreamId, State2#state.last_peer_stream_id)},

                    %% Notify owner
                    {Method, Path, OtherHeaders} = extract_request_headers(Headers),
                    notify_owner({h2, self(), {request, StreamId, Method, Path, OtherHeaders}}, State3),

                    case EndStream of
                        true -> ok;
                        false -> ok
                    end,
                    {ok, connected, State3};

                client ->
                    %% Check if this is a response or trailers
                    case Stream#stream.response_headers of
                        [] ->
                            %% This is a response (first HEADERS on this stream)
                            Stream1 = Stream#stream{
                                state = case EndStream of true -> half_closed_remote; false -> open end,
                                response_headers = Headers
                            },
                            State2 = put_stream(StreamId, Stream1, State1),

                            %% Notify owner
                            Status = extract_status(Headers),
                            OtherHeaders = lists:filter(fun({N, _}) -> not is_pseudo_header(N) end, Headers),
                            notify_owner({h2, self(), {response, StreamId, Status, OtherHeaders}}, State2),

                            case EndStream of
                                true ->
                                    State3 = close_stream(StreamId, State2),
                                    {ok, connected, State3};
                                false ->
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

%% Validate pseudo-headers per RFC 7540 §8.1.2.3 (requests) and §8.1.2.4 (responses):
%% - pseudo-headers must precede regular headers
%% - unknown pseudo-headers MUST be rejected
%% - requests MUST contain :method, :scheme, :path (except CONNECT); :authority optional
%% - responses MUST contain :status
%% - no duplicate pseudo-headers
validate_pseudo_headers(Mode, Headers) ->
    case check_pseudo_order(Headers) of
        ok -> check_pseudo_set(Mode, Headers);
        Err -> Err
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

extract_status(Headers) ->
    case proplists:get_value(<<":status">>, Headers) of
        undefined -> 200;
        StatusBin -> binary_to_integer(StatusBin)
    end.

is_pseudo_header(<<$:, _/binary>>) -> true;
is_pseudo_header(_) -> false.

%% ============================================================================
%% Internal: Data Frame Handling
%% ============================================================================

handle_data_frame(StreamId, Data, EndStream, #state{streams = Streams, recv_conn_window_size = ConnWindow} = State) ->
    DataSize = byte_size(Data),

    %% Check connection flow control
    if
        DataSize > ConnWindow ->
            {error, flow_control_error, State};
        true ->
            case maps:find(StreamId, Streams) of
                {ok, #stream{state = StreamState, recv_window_size = StreamWindow} = Stream} when StreamState == open; StreamState == half_closed_local ->
                    if
                        DataSize > StreamWindow ->
                            send_rst_stream(StreamId, flow_control_error, State),
                            State1 = close_stream(StreamId, State),
                            {ok, connected, State1};
                        true ->
                            %% Update windows
                            NewConnWindow = ConnWindow - DataSize,
                            NewStreamWindow = StreamWindow - DataSize,
                            Stream1 = Stream#stream{recv_window_size = NewStreamWindow},

                            %% Update stream state if end of stream
                            Stream2 = case EndStream of
                                true ->
                                    case StreamState of
                                        open -> Stream1#stream{state = half_closed_remote};
                                        half_closed_local -> Stream1#stream{state = closed}
                                    end;
                                false ->
                                    Stream1
                            end,

                            State1 = State#state{
                                recv_conn_window_size = NewConnWindow,
                                streams = maps:put(StreamId, Stream2, Streams)
                            },

                            %% Notify owner
                            notify_owner({h2, self(), {data, StreamId, Data, EndStream}}, State1),

                            %% Send WINDOW_UPDATE if needed
                            State2 = maybe_send_window_update(StreamId, DataSize, State1),

                            case EndStream andalso Stream2#stream.state == closed of
                                true ->
                                    State3 = close_stream(StreamId, State2),
                                    {ok, connected, State3};
                                false ->
                                    {ok, connected, State2}
                            end
                    end;
                {ok, _} ->
                    send_rst_stream(StreamId, stream_closed, State),
                    {ok, connected, State};
                error ->
                    %% Unknown stream
                    {error, protocol_error, State}
            end
    end.

maybe_send_window_update(StreamId, _DataSize, #state{recv_conn_window_size = ConnWindow,
                                                     local_settings = Settings,
                                                     streams = Streams} = State) ->
    InitialWindow = h2_settings:get(initial_window_size, Settings),
    Threshold = InitialWindow div 2,

    %% Connection-level window update
    State1 = case ConnWindow < Threshold of
        true ->
            ConnIncrement = InitialWindow - ConnWindow,
            send_frame(h2_frame:window_update(0, ConnIncrement), State),
            State#state{recv_conn_window_size = ConnWindow + ConnIncrement};
        false ->
            State
    end,

    %% Stream-level window update
    case maps:find(StreamId, Streams) of
        {ok, #stream{recv_window_size = StreamWindow} = Stream} when StreamWindow < Threshold ->
            StreamIncrement = InitialWindow - StreamWindow,
            send_frame(h2_frame:window_update(StreamId, StreamIncrement), State1),
            Stream1 = Stream#stream{recv_window_size = StreamWindow + StreamIncrement},
            State1#state{streams = maps:put(StreamId, Stream1, Streams)};
        _ ->
            State1
    end.

%% ============================================================================
%% Internal: Send Operations
%% ============================================================================

handle_send_request(From, Method, Path, Headers, EndStream, #state{mode = client, next_stream_id = StreamId,
                                                        peer_settings = PeerSettings,
                                                        encode_context = EncCtx} = State) ->
    %% Check max concurrent streams
    MaxStreams = h2_settings:get(max_concurrent_streams, PeerSettings),
    ActiveStreams = count_active_streams(State),

    case MaxStreams of
        N when is_integer(N), ActiveStreams >= N ->
            {keep_state, State, [{reply, From, {error, max_streams_exceeded}}]};
        _ ->
            %% Build pseudo-headers
            Scheme = <<"https">>,  % Default to https
            Authority = proplists:get_value(<<"host">>, Headers, <<>>),
            AllHeaders = [
                {<<":method">>, Method},
                {<<":path">>, Path},
                {<<":scheme">>, Scheme},
                {<<":authority">>, Authority}
                | lists:filter(fun({N1, _}) -> N1 =/= <<"host">> end, Headers)
            ],

            %% Encode headers
            {HeaderBlock, EncCtx1} = h2_hpack:encode(AllHeaders, EncCtx),

            %% Create stream with appropriate state
            InitialWindow = h2_settings:get(initial_window_size, PeerSettings),
            RecvWindow = h2_settings:get(initial_window_size, State#state.local_settings),
            StreamState = case EndStream of
                true -> half_closed_local;
                false -> open
            end,
            Stream = #stream{
                id = StreamId,
                state = StreamState,
                window_size = InitialWindow,
                recv_window_size = RecvWindow
            },

            %% Send HEADERS frame with END_STREAM flag as specified
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
                                                              peer_settings = PeerSettings,
                                                              encode_context = EncCtx} = State) ->
    MaxStreams = h2_settings:get(max_concurrent_streams, PeerSettings),
    ActiveStreams = count_active_streams(State),
    case MaxStreams of
        N when is_integer(N), ActiveStreams >= N ->
            {keep_state, State, [{reply, From, {error, max_streams_exceeded}}]};
        _ ->
            {HeaderBlock, EncCtx1} = h2_hpack:encode(Headers, EncCtx),
            InitialWindow = h2_settings:get(initial_window_size, PeerSettings),
            RecvWindow = h2_settings:get(initial_window_size, State#state.local_settings),
            StreamState = case EndStream of true -> half_closed_local; false -> open end,
            Stream = #stream{
                id = StreamId,
                state = StreamState,
                window_size = InitialWindow,
                recv_window_size = RecvWindow
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
        {ok, #stream{state = StreamState} = Stream} when StreamState == open; StreamState == half_closed_remote ->
            %% Build response headers
            StatusBin = integer_to_binary(Status),
            AllHeaders = [{<<":status">>, StatusBin} | Headers],

            %% Encode headers
            {HeaderBlock, EncCtx1} = h2_hpack:encode(AllHeaders, EncCtx),

            %% Send HEADERS frame (without END_STREAM, will send data separately)
            Frame = h2_frame:headers(StreamId, HeaderBlock, false),
            send_frame(Frame, State),

            Stream1 = Stream#stream{response_headers = AllHeaders},
            State1 = State#state{
                encode_context = EncCtx1,
                streams = maps:put(StreamId, Stream1, Streams)
            },

            {keep_state, State1, [{reply, From, ok}]};
        {ok, _} ->
            {keep_state, State, [{reply, From, {error, invalid_stream_state}}]};
        error ->
            {keep_state, State, [{reply, From, {error, unknown_stream}}]}
    end;

handle_send_response(From, _StreamId, _Status, _Headers, State) ->
    {keep_state, State, [{reply, From, {error, not_server}}]}.

handle_send_data(From, StreamId, Data, EndStream, #state{streams = Streams, conn_window_size = ConnWindow,
                                                          peer_settings = PeerSettings} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{state = StreamState, window_size = StreamWindow, send_buffer = Buffer} = Stream}
          when StreamState == open; StreamState == half_closed_remote ->
            MaxFrameSize = h2_settings:get(max_frame_size, PeerSettings),

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

handle_send_goaway(From, ErrorCode, CurrentState, State) ->
    State1 = send_goaway_frame(State#state.last_peer_stream_id, ErrorCode, State),
    NextState = case CurrentState of
        goaway_received -> closing;
        _ -> goaway_sent
    end,
    {next_state, NextState, State1, [{reply, From, ok}]}.

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

get_or_create_stream(StreamId, #state{streams = Streams, peer_settings = PeerSettings,
                                       local_settings = LocalSettings} = _State) ->
    case maps:find(StreamId, Streams) of
        {ok, Stream} ->
            Stream;
        error ->
            InitialWindow = h2_settings:get(initial_window_size, PeerSettings),
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
                                      peer_settings = PeerSettings} = State) ->
    case maps:find(StreamId, Streams) of
        {ok, #stream{send_buffer = <<>>}} ->
            State;
        {ok, #stream{send_buffer = Buffer, window_size = StreamWindow,
                     pending_end_stream = PendingEnd, state = StreamState} = Stream} ->
            MaxFrameSize = h2_settings:get(max_frame_size, PeerSettings),
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
    %% Send connection preface
    ok = Transport:send(Socket, ?H2_PREFACE),
    %% Send initial SETTINGS
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
    Owner ! Msg.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% Basic unit tests will be in the test suite
-endif.
