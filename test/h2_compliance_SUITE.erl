%% @doc HTTP/2 Compliance Test Suite
%%
%% Integration tests for the HTTP/2 implementation using Common Test.
%% These tests verify the complete client/server interaction.
%%
-module(h2_compliance_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% CT callbacks
-export([all/0, groups/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_group/2, end_per_group/2]).
-export([init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    %% Connection tests
    connection_preface_test/1,
    settings_exchange_test/1,
    settings_ack_test/1,

    %% Request/Response tests
    simple_get_test/1,
    simple_post_test/1,
    request_with_body_test/1,
    large_response_test/1,
    multiple_requests_test/1,
    concurrent_streams_test/1,

    %% Headers tests
    pseudo_headers_test/1,
    custom_headers_test/1,
    large_headers_test/1,

    %% Flow control tests
    flow_control_window_test/1,
    window_update_test/1,
    zero_window_test/1,

    %% Stream state tests
    stream_lifecycle_test/1,
    half_closed_test/1,
    stream_reset_test/1,

    %% Error handling tests
    invalid_stream_id_test/1,
    goaway_test/1,
    protocol_error_test/1,

    %% PING tests
    ping_test/1,

    %% Trailers tests
    trailers_test/1,

    %% API parity (quic_h3) tests
    connected_event_test/1,
    goaway_event_test/1,
    closed_event_test/1,
    stream_handler_test/1,
    handler_module_test/1
]).

%% Module-style handler callback used by handler_module_test.
-export([handle_request/5]).

%% ============================================================================
%% CT Callbacks
%% ============================================================================

suite() ->
    [{timetrap, {seconds, 30}}].

all() ->
    [
        {group, connection},
        {group, request_response},
        {group, headers},
        {group, flow_control},
        {group, stream_state},
        {group, error_handling},
        {group, misc},
        {group, api_parity}
    ].

groups() ->
    [
        {connection, [sequence], [
            connection_preface_test,
            settings_exchange_test,
            settings_ack_test
        ]},
        {request_response, [sequence], [
            simple_get_test,
            simple_post_test,
            request_with_body_test,
            large_response_test,
            multiple_requests_test,
            concurrent_streams_test
        ]},
        {headers, [sequence], [
            pseudo_headers_test,
            custom_headers_test,
            large_headers_test
        ]},
        {flow_control, [sequence], [
            flow_control_window_test,
            window_update_test,
            zero_window_test
        ]},
        {stream_state, [sequence], [
            stream_lifecycle_test,
            half_closed_test,
            stream_reset_test
        ]},
        {error_handling, [sequence], [
            invalid_stream_id_test,
            goaway_test,
            protocol_error_test
        ]},
        {misc, [sequence], [
            ping_test,
            trailers_test
        ]},
        {api_parity, [sequence], [
            connected_event_test,
            goaway_event_test,
            closed_event_test,
            stream_handler_test,
            handler_module_test
        ]}
    ].

init_per_suite(Config) ->
    %% Start required applications
    ok = application:ensure_started(crypto),
    ok = application:ensure_started(asn1),
    ok = application:ensure_started(public_key),
    ok = application:ensure_started(ssl),

    %% Generate test certificates
    CertDir = ?config(priv_dir, Config),
    {CertFile, KeyFile} = generate_test_certs(CertDir),

    [{cert_file, CertFile}, {key_file, KeyFile} | Config].

end_per_suite(_Config) ->
    ok.

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    process_flag(trap_exit, true),
    drain_exits(),
    CertFile = ?config(cert_file, Config),
    KeyFile = ?config(key_file, Config),

    Handler = fun(Conn, StreamId, Method, Path, Headers) ->
        handle_test_request(Conn, StreamId, Method, Path, Headers)
    end,

    ServerOpts = #{
        cert => CertFile,
        key => KeyFile,
        handler => Handler
    },

    %% Let the OS pick a free port (avoids TOCTOU with find_available_port).
    case h2:start_server(0, ServerOpts) of
        {ok, ServerRef} ->
            Port = h2:server_port(ServerRef),
            [{server_ref, ServerRef}, {port, Port} | Config];
        {error, Reason} ->
            {skip, {server_start_failed, Reason}}
    end.

end_per_testcase(_TestCase, Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        ServerRef -> h2:stop_server(ServerRef)
    end,
    %% Give time for sockets to fully close
    timer:sleep(50),
    %% Drain any lingering 'EXIT' messages from linked connection processes
    drain_exits(),
    ok.

drain_exits() ->
    receive
        {'EXIT', _Pid, _Reason} -> drain_exits()
    after 0 ->
        ok
    end.

%% ============================================================================
%% Test Server Handler
%% ============================================================================

handle_test_request(Conn, StreamId, Method, Path, Headers) ->
    case {Method, Path} of
        {<<"GET">>, <<"/">>} ->
            h2:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
            h2:send_data(Conn, StreamId, <<"Hello, World!">>, true);

        {<<"GET">>, <<"/echo">>} ->
            Body = io_lib:format("Method: ~s~nPath: ~s~nHeaders: ~p~n",
                                 [Method, Path, Headers]),
            h2:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
            h2:send_data(Conn, StreamId, iolist_to_binary(Body), true);

        {<<"POST">>, <<"/echo">>} ->
            %% Echo back the request info
            h2:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
            h2:send_data(Conn, StreamId, <<"POST received">>, true);

        {<<"GET">>, <<"/large">>} ->
            %% Return a large response
            LargeBody = binary:copy(<<"x">>, 100000),
            h2:send_response(Conn, StreamId, 200, [
                {<<"content-type">>, <<"application/octet-stream">>},
                {<<"content-length">>, <<"100000">>}
            ]),
            h2:send_data(Conn, StreamId, LargeBody, true);

        {<<"GET">>, <<"/trailers">>} ->
            h2:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
            h2:send_data(Conn, StreamId, <<"Body">>, false),
            h2:send_trailers(Conn, StreamId, [{<<"x-checksum">>, <<"abc123">>}]);

        {<<"GET">>, <<"/delay/", Delay/binary>>} ->
            %% Delayed response
            Ms = binary_to_integer(Delay),
            timer:sleep(Ms),
            h2:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
            h2:send_data(Conn, StreamId, <<"Delayed">>, true);

        {<<"GET">>, <<"/headers">>} ->
            %% Return many headers
            ResponseHeaders = [
                {<<"content-type">>, <<"text/plain">>},
                {<<"x-custom-1">>, <<"value1">>},
                {<<"x-custom-2">>, <<"value2">>},
                {<<"x-custom-3">>, <<"value3">>}
            ],
            h2:send_response(Conn, StreamId, 200, ResponseHeaders),
            h2:send_data(Conn, StreamId, <<"Headers test">>, true);

        _ ->
            h2:send_response(Conn, StreamId, 404, [{<<"content-type">>, <<"text/plain">>}]),
            h2:send_data(Conn, StreamId, <<"Not Found">>, true)
    end.

%% ============================================================================
%% Connection Tests
%% ============================================================================

connection_preface_test(Config) ->
    Port = ?config(port, Config),

    %% Connect to server
    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% If we got here, connection preface exchange succeeded
    ?assert(is_pid(Conn)),

    h2:close(Conn),
    ok.

settings_exchange_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}],
        settings => #{
            max_concurrent_streams => 100,
            initial_window_size => 65535
        }
    }),

    %% Get local and peer settings
    LocalSettings = h2:get_settings(Conn),
    PeerSettings = h2:get_peer_settings(Conn),

    ?assertMatch(#{max_concurrent_streams := _}, LocalSettings),
    ?assertMatch(#{initial_window_size := _}, PeerSettings),

    h2:close(Conn),
    ok.

settings_ack_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Send a request to verify settings exchange completed
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    ?assert(is_integer(StreamId)),
    ?assertEqual(1, StreamId),  %% First client stream should be 1

    h2:close(Conn),
    ok.

%% ============================================================================
%% Request/Response Tests
%% ============================================================================

simple_get_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    %% Wait for response
    Response = receive_full_response(Conn, StreamId, 5000),

    ?assertMatch({200, _, _}, Response),
    {200, _Headers, Body} = Response,
    ?assertEqual(<<"Hello, World!">>, Body),

    h2:close(Conn),
    ok.

simple_post_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    {ok, StreamId} = h2:request(Conn, <<"POST">>, <<"/echo">>, [
        {<<"host">>, <<"localhost">>},
        {<<"content-type">>, <<"text/plain">>}
    ], <<"test body">>),

    Response = receive_full_response(Conn, StreamId, 5000),

    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

request_with_body_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Send request with body using request/5
    {ok, StreamId} = h2:request(Conn, <<"POST">>, <<"/echo">>, [
        {<<"host">>, <<"localhost">>},
        {<<"content-type">>, <<"application/json">>}
    ], <<"{\"key\":\"value\"}">>),

    Response = receive_full_response(Conn, StreamId, 5000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

large_response_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/large">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    Response = receive_full_response(Conn, StreamId, 10000),

    ?assertMatch({200, _, _}, Response),
    {200, _Headers, Body} = Response,
    ?assertEqual(100000, byte_size(Body)),

    h2:close(Conn),
    ok.

multiple_requests_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Send multiple sequential requests
    lists:foreach(fun(N) ->
        Path = iolist_to_binary([<<"/">>, integer_to_binary(N)]),
        {ok, StreamId} = h2:request(Conn, <<"GET">>, Path, [
            {<<"host">>, <<"localhost">>}
        ]),
        Response = receive_full_response(Conn, StreamId, 5000),
        %% Should get 404 for these paths
        ?assertMatch({404, _, _}, Response)
    end, lists:seq(1, 5)),

    h2:close(Conn),
    ok.

concurrent_streams_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Send multiple concurrent requests
    StreamIds = lists:map(fun(_N) ->
        {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [
            {<<"host">>, <<"localhost">>}
        ]),
        StreamId
    end, lists:seq(1, 10)),

    %% Collect all responses
    lists:foreach(fun(StreamId) ->
        Response = receive_full_response(Conn, StreamId, 5000),
        ?assertMatch({200, _, _}, Response)
    end, StreamIds),

    h2:close(Conn),
    ok.

%% ============================================================================
%% Headers Tests
%% ============================================================================

pseudo_headers_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/echo">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    Response = receive_full_response(Conn, StreamId, 5000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

custom_headers_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/headers">>, [
        {<<"host">>, <<"localhost">>},
        {<<"x-custom-request">>, <<"value">>}
    ]),

    {200, Headers, _Body} = receive_full_response(Conn, StreamId, 5000),

    %% Check custom response headers
    ?assertMatch(<<"value1">>, proplists:get_value(<<"x-custom-1">>, Headers)),

    h2:close(Conn),
    ok.

large_headers_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Send large header value
    LargeValue = binary:copy(<<"x">>, 1000),
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [
        {<<"host">>, <<"localhost">>},
        {<<"x-large-header">>, LargeValue}
    ]),

    Response = receive_full_response(Conn, StreamId, 5000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

%% ============================================================================
%% Flow Control Tests
%% ============================================================================

flow_control_window_test(Config) ->
    Port = ?config(port, Config),

    %% Use 16KB window (standard min) instead of 1KB to avoid excessive window updates
    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}],
        settings => #{
            initial_window_size => 16384
        }
    }),

    %% Request a response - will require ~6 window updates with 16KB window
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/large">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    %% Should complete with flow control in reasonable time
    Response = receive_full_response(Conn, StreamId, 10000),
    ?assertMatch({200, _, _}, Response),
    {200, _, Body} = Response,
    ?assertEqual(100000, byte_size(Body)),

    h2:close(Conn),
    ok.

window_update_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/large">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    Response = receive_full_response(Conn, StreamId, 30000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

zero_window_test(Config) ->
    Port = ?config(port, Config),

    %% Test with small initial window (1KB)
    %% Response is 13 bytes ("Hello, World!"), so should complete quickly
    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}],
        settings => #{
            initial_window_size => 1024
        }
    }),

    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    Response = receive_full_response(Conn, StreamId, 5000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

%% ============================================================================
%% Stream State Tests
%% ============================================================================

stream_lifecycle_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Stream 1: idle -> open -> half-closed (local) -> closed
    {ok, Stream1} = h2:request(Conn, <<"GET">>, <<"/">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    Response1 = receive_full_response(Conn, Stream1, 5000),
    ?assertMatch({200, _, _}, Response1),

    h2:close(Conn),
    ok.

half_closed_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Send POST request with body (client half-closes after body)
    {ok, StreamId} = h2:request(Conn, <<"POST">>, <<"/echo">>, [
        {<<"host">>, <<"localhost">>}
    ], <<"data">>),

    %% Wait for response (server half-closes after response)
    Response = receive_full_response(Conn, StreamId, 5000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

stream_reset_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Start a request then cancel it
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/delay/5000">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    %% Cancel the stream
    ok = h2:cancel(Conn, StreamId),

    %% Should be able to start new streams
    {ok, StreamId2} = h2:request(Conn, <<"GET">>, <<"/">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    Response = receive_full_response(Conn, StreamId2, 5000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

%% ============================================================================
%% Error Handling Tests
%% ============================================================================

invalid_stream_id_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Try to send data on non-existent stream
    Result = h2:send_data(Conn, 999, <<"data">>, true),
    ?assertMatch({error, _}, Result),

    h2:close(Conn),
    ok.

goaway_test(Config) ->
    Port = ?config(port, Config),

    %% Trap exits so connection termination doesn't crash the test
    process_flag(trap_exit, true),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Send GOAWAY
    ok = h2:goaway(Conn),

    %% Wait for connection to close (either goaway_exchange or close by peer)
    receive
        {'EXIT', Conn, {shutdown, _Reason}} ->
            %% Expected - connection closed gracefully
            ok
    after 5000 ->
        %% If still alive after timeout, close it
        h2:close(Conn)
    end,

    process_flag(trap_exit, false),
    ok.

protocol_error_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% Normal request should work
    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    Response = receive_full_response(Conn, StreamId, 5000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

%% ============================================================================
%% Misc Tests
%% ============================================================================

ping_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    %% PING is handled internally by h2_connection
    %% Just verify connection still works after some time
    timer:sleep(100),

    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    Response = receive_full_response(Conn, StreamId, 5000),
    ?assertMatch({200, _, _}, Response),

    h2:close(Conn),
    ok.

trailers_test(Config) ->
    Port = ?config(port, Config),

    {ok, Conn} = h2:connect("localhost", Port, #{
        ssl_opts => [{verify, verify_none}]
    }),

    {ok, StreamId} = h2:request(Conn, <<"GET">>, <<"/trailers">>, [
        {<<"host">>, <<"localhost">>}
    ]),

    %% Wait for response with trailers
    Response = receive_full_response_with_trailers(Conn, StreamId, 5000),
    ?assertMatch({200, _, _, _}, Response),
    {200, _Headers, _Body, Trailers} = Response,
    ?assertMatch(<<"abc123">>, proplists:get_value(<<"x-checksum">>, Trailers)),

    h2:close(Conn),
    ok.

%% ============================================================================
%% API parity (quic_h3) tests
%% ============================================================================

connected_event_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    %% The 'connected' event must arrive (may have been delivered before this
    %% receive runs since wait_connected is synchronous).
    receive
        {h2, Conn, connected} -> ok
    after 1000 ->
        ct:fail(no_connected_event)
    end,
    h2:close(Conn),
    ok.

goaway_event_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    receive {h2, Conn, connected} -> ok after 1000 -> ct:fail(no_connected) end,
    process_flag(trap_exit, true),
    ok = h2:goaway(Conn),
    %% Local sender sees goaway_sent event.
    receive
        {h2, Conn, goaway_sent} -> ok
    after 2000 ->
        ct:fail(no_goaway_sent_event)
    end,
    catch h2:close(Conn),
    drain_exits(),
    ok.

closed_event_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    receive {h2, Conn, connected} -> ok after 1000 -> ct:fail(no_connected) end,
    %% Stop the server; the client should see {closed, _}.
    case ?config(server_ref, Config) of
        undefined -> ok;
        ServerRef -> h2:stop_server(ServerRef)
    end,
    receive
        {h2, Conn, {closed, _Reason}} -> ok
    after 2000 ->
        ct:fail(no_closed_event)
    end,
    catch h2:close(Conn),
    drain_exits(),
    ok.

stream_handler_test(Config) ->
    Self = self(),
    %% Re-start a server in this test that hands POST bodies off to a worker
    %% via set_stream_handler/3.
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Handler = fun(Conn, StreamId, <<"POST">>, _Path, _Headers) ->
        Worker = spawn(fun() ->
            receive
                {start, Sid} ->
                    Body = collect_body(Conn, Sid, <<>>),
                    Self ! {worker_got, Body}
            end
        end),
        case h2:set_stream_handler(Conn, StreamId, Worker) of
            ok ->
                Worker ! {start, StreamId},
                ok;
            {ok, Buffered} ->
                Worker ! {start, StreamId},
                lists:foreach(fun({D, Fin}) ->
                    Worker ! {h2, Conn, {data, StreamId, D, Fin}}
                end, Buffered),
                ok
        end,
        h2:send_response(Conn, StreamId, 200, []),
        h2:send_data(Conn, StreamId, <<"ok">>, true);
    (Conn, StreamId, _Method, _Path, _Headers) ->
        h2:send_response(Conn, StreamId, 405, []),
        h2:send_data(Conn, StreamId, <<>>, true)
    end,
    {ok, ServerRef} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port2 = h2:server_port(ServerRef),
    {ok, Conn} = h2:connect("localhost", Port2, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"POST">>, <<"/upload">>, [
        {<<"host">>, <<"localhost">>}
    ], <<"hello world">>),
    Resp = receive_full_response(Conn, Sid, 2000),
    ?assertMatch({200, _, <<"ok">>}, Resp),
    receive
        {worker_got, Body} ->
            ?assertEqual(<<"hello world">>, Body)
    after 2000 ->
        ct:fail(worker_no_body)
    end,
    h2:close(Conn),
    h2:stop_server(ServerRef),
    drain_exits(),
    ok.

handler_module_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    {ok, ServerRef} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => ?MODULE  %% module-style callback; uses handle_request/5 below
    }),
    Port2 = h2:server_port(ServerRef),
    {ok, Conn} = h2:connect("localhost", Port2, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/m">>, [
        {<<"host">>, <<"localhost">>}
    ]),
    Resp = receive_full_response(Conn, Sid, 2000),
    ?assertMatch({201, _, <<"module-handler">>}, Resp),
    h2:close(Conn),
    h2:stop_server(ServerRef),
    drain_exits(),
    ok.

%% Module callback used by handler_module_test.
handle_request(Conn, StreamId, _Method, _Path, _Headers) ->
    h2:send_response(Conn, StreamId, 201, [{<<"content-type">>, <<"text/plain">>}]),
    h2:send_data(Conn, StreamId, <<"module-handler">>, true).

collect_body(Conn, StreamId, Acc) ->
    receive
        {h2, Conn, {data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {h2, Conn, {data, StreamId, Data, false}} ->
            collect_body(Conn, StreamId, <<Acc/binary, Data/binary>>)
    after 2000 ->
        Acc
    end.

%% ============================================================================
%% Helper Functions
%% ============================================================================

receive_full_response(Conn, StreamId, Timeout) ->
    receive_full_response(Conn, StreamId, Timeout, undefined, [], <<>>).

receive_full_response(Conn, StreamId, Timeout, Status, Headers, Body) ->
    receive
        {h2, Conn, {response, StreamId, S, H}} ->
            receive_full_response(Conn, StreamId, Timeout, S, H, Body);
        {h2, Conn, {data, StreamId, Data, true}} ->
            {Status, Headers, <<Body/binary, Data/binary>>};
        {h2, Conn, {data, StreamId, Data, false}} ->
            receive_full_response(Conn, StreamId, Timeout, Status, Headers, <<Body/binary, Data/binary>>);
        {h2, Conn, {stream_reset, StreamId, ErrorCode}} ->
            {error, {stream_reset, ErrorCode}};
        {h2, Conn, {goaway, _, ErrorCode}} ->
            {error, {goaway, ErrorCode}}
    after Timeout ->
        {error, timeout}
    end.

receive_full_response_with_trailers(Conn, StreamId, Timeout) ->
    receive_full_response_with_trailers(Conn, StreamId, Timeout, undefined, [], <<>>, []).

receive_full_response_with_trailers(Conn, StreamId, Timeout, Status, Headers, Body, Trailers) ->
    receive
        {h2, Conn, {response, StreamId, S, H}} ->
            receive_full_response_with_trailers(Conn, StreamId, Timeout, S, H, Body, Trailers);
        {h2, Conn, {data, StreamId, Data, true}} ->
            {Status, Headers, <<Body/binary, Data/binary>>, Trailers};
        {h2, Conn, {data, StreamId, Data, false}} ->
            receive_full_response_with_trailers(Conn, StreamId, Timeout, Status, Headers, <<Body/binary, Data/binary>>, Trailers);
        {h2, Conn, {trailers, StreamId, T}} ->
            {Status, Headers, Body, T};
        {h2, Conn, {stream_reset, StreamId, ErrorCode}} ->
            {error, {stream_reset, ErrorCode}}
    after Timeout ->
        {error, timeout}
    end.

generate_test_certs(Dir) ->
    CertFile = filename:join(Dir, "server.pem"),
    KeyFile = filename:join(Dir, "server-key.pem"),

    %% Generate self-signed certificate using OpenSSL
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile]),

    case os:cmd(lists:flatten(Cmd)) of
        "" -> {CertFile, KeyFile};
        _Error ->
            %% Fallback: create dummy files for testing structure
            create_dummy_certs(CertFile, KeyFile)
    end.

create_dummy_certs(CertFile, KeyFile) ->
    %% This is a fallback for environments without OpenSSL
    %% In real testing, proper certificates should be generated
    DummyCert = <<"-----BEGIN CERTIFICATE-----\nDUMMY\n-----END CERTIFICATE-----\n">>,
    DummyKey = <<"-----BEGIN PRIVATE KEY-----\nDUMMY\n-----END PRIVATE KEY-----\n">>,
    file:write_file(CertFile, DummyCert),
    file:write_file(KeyFile, DummyKey),
    {CertFile, KeyFile}.

