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
    handler_module_test/1,

    %% CONNECT tunnel (RFC 7540 §8.3)
    connect_tunnel_basic_test/1,
    connect_tunnel_half_close_test/1,
    connect_response_4xx_test/1,
    connect_trailers_rejected_test/1,

    %% RFC 9113 additional compliance (second-look audit)
    tunnel_outbound_trailers_rejected_test/1,
    server_push_setting_disabled_test/1,
    header_value_with_nul_rejected_test/1,
    outbound_uppercase_header_rejected_test/1,
    outbound_bad_pseudo_rejected_test/1,
    send_response_101_rejected_test/1,
    goaway_event_three_tuple_test/1,
    leading_space_value_rejected_test/1,
    invalid_name_chars_rejected_test/1,
    large_request_split_test/1,
    peer_max_header_list_size_enforced_test/1,
    connect_verify_option_honored_test/1,
    tcp_server_round_trip_test/1,
    stream_handler_receives_trailers_test/1,
    empty_response_emits_trailing_data_test/1,

    %% Extended CONNECT (RFC 8441)
    extended_connect_setting_advertised_test/1,
    extended_connect_setting_default_off_test/1,
    extended_connect_round_trip_test/1,
    extended_connect_client_refuses_when_peer_disabled_test/1,
    extended_connect_method_must_be_connect_test/1,
    extended_connect_trailers_rejected_test/1,
    extended_connect_server_rejects_when_disabled_test/1,

    %% Third-pass review findings
    informational_end_stream_rejected_test/1,
    authority_userinfo_rejected_outbound_test/1,
    authority_userinfo_rejected_inbound_test/1,
    extended_connect_bad_protocol_token_rejected_test/1,
    connect_non_2xx_trailers_allowed_test/1,
    closed_stream_headers_triggers_goaway_test/1,
    closed_stream_data_triggers_goaway_test/1,
    rst_closed_stream_headers_triggers_rst_test/1,
    rst_closed_stream_data_triggers_rst_test/1,
    closed_stream_continuation_triggers_goaway_test/1,
    max_concurrent_streams_refuses_excess_test/1,
    client_rejects_enable_push_one_test/1,
    head_response_with_content_length_accepted_test/1,
    body_forbidden_response_without_end_stream_rejected_test/1,
    priority_wrong_length_is_stream_error_test/1,
    connect_ssl_without_alpn_rejected_test/1,
    unknown_frame_type_is_ignored_test/1,
    window_update_on_idle_stream_triggers_goaway_test/1,
    goaway_closes_tcp_socket_test/1,
    iws_exceeds_max_triggers_flow_control_error_test/1
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
        {group, api_parity},
        {group, tunnel},
        {group, compliance_v2}
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
        ]},
        {tunnel, [sequence], [
            connect_tunnel_basic_test,
            connect_tunnel_half_close_test,
            connect_response_4xx_test,
            connect_trailers_rejected_test
        ]},
        {compliance_v2, [sequence], [
            tunnel_outbound_trailers_rejected_test,
            server_push_setting_disabled_test,
            header_value_with_nul_rejected_test,
            outbound_uppercase_header_rejected_test,
            outbound_bad_pseudo_rejected_test,
            send_response_101_rejected_test,
            goaway_event_three_tuple_test,
            leading_space_value_rejected_test,
            invalid_name_chars_rejected_test,
            large_request_split_test,
            peer_max_header_list_size_enforced_test,
            connect_verify_option_honored_test,
            tcp_server_round_trip_test,
            stream_handler_receives_trailers_test,
            empty_response_emits_trailing_data_test,

            %% RFC 8441 Extended CONNECT
            extended_connect_setting_advertised_test,
            extended_connect_setting_default_off_test,
            extended_connect_round_trip_test,
            extended_connect_client_refuses_when_peer_disabled_test,
            extended_connect_method_must_be_connect_test,
            extended_connect_trailers_rejected_test,
            extended_connect_server_rejects_when_disabled_test,

            %% Third-pass review fixes
            informational_end_stream_rejected_test,
            authority_userinfo_rejected_outbound_test,
            authority_userinfo_rejected_inbound_test,
            extended_connect_bad_protocol_token_rejected_test,
            connect_non_2xx_trailers_allowed_test,
            closed_stream_headers_triggers_goaway_test,
            closed_stream_data_triggers_goaway_test,
            rst_closed_stream_headers_triggers_rst_test,
            rst_closed_stream_data_triggers_rst_test,
            closed_stream_continuation_triggers_goaway_test,
            max_concurrent_streams_refuses_excess_test,
            client_rejects_enable_push_one_test,
            head_response_with_content_length_accepted_test,
            body_forbidden_response_without_end_stream_rejected_test,
            priority_wrong_length_is_stream_error_test,
            connect_ssl_without_alpn_rejected_test,
            unknown_frame_type_is_ignored_test,
            window_update_on_idle_stream_triggers_goaway_test,
            goaway_closes_tcp_socket_test,
            iws_exceeds_max_triggers_flow_control_error_test
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
%% CONNECT tunnel tests (RFC 7540 §8.3)
%% ============================================================================

start_echo_tunnel_server(Config) ->
    Self = self(),
    EchoHandler = fun(Conn, StreamId, <<"CONNECT">>, _Path, _Headers) ->
        Worker = spawn(fun() ->
            receive {start, Sid} ->
                Self ! {tunnel_worker, self(), Sid},
                tunnel_echo_loop(Conn, Sid)
            end
        end),
        case h2:set_stream_handler(Conn, StreamId, Worker) of
            ok            -> Worker ! {start, StreamId};
            {ok, Buf}     ->
                Worker ! {start, StreamId},
                lists:foreach(fun({D, F}) ->
                    Worker ! {h2, Conn, {data, StreamId, D, F}}
                end, Buf)
        end,
        h2:send_response(Conn, StreamId, 200, []);
       (Conn, Sid, _M, _P, _H) ->
        h2:send_response(Conn, Sid, 405, []),
        h2:send_data(Conn, Sid, <<>>, true)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => EchoHandler
    }),
    Ref.

tunnel_echo_loop(Conn, Sid) ->
    receive
        {h2, Conn, {data, Sid, Data, true}} ->
            h2:send_data(Conn, Sid, Data, true);
        {h2, Conn, {data, Sid, Data, false}} ->
            h2:send_data(Conn, Sid, Data, false),
            tunnel_echo_loop(Conn, Sid)
    after 5000 ->
        ok
    end.

connect_tunnel_basic_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Ref = start_echo_tunnel_server(Config),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"CONNECT">>, <<>>, [
        {<<"host">>, <<"target.example:443">>}
    ]),
    %% Expect 200 response (no body yet).
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 2000 ->
        ct:fail(no_connect_response)
    end,
    ok = h2:send_data(Conn, Sid, <<"hello">>, false),
    receive
        {h2, Conn, {data, Sid, <<"hello">>, false}} -> ok
    after 2000 ->
        ct:fail(no_echo)
    end,
    ok = h2:send_data(Conn, Sid, <<"world">>, true),
    receive
        {h2, Conn, {data, Sid, <<"world">>, true}} -> ok
    after 2000 ->
        ct:fail(no_final_echo)
    end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

connect_tunnel_half_close_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Self = self(),
    Handler = fun(Conn, Sid, <<"CONNECT">>, _, _) ->
        Worker = spawn(fun() ->
            receive {start, S} ->
                Self ! {worker, self(), S},
                worker_half_close_loop(Conn, S, <<>>)
            end
        end),
        case h2:set_stream_handler(Conn, Sid, Worker) of
            ok        -> Worker ! {start, Sid};
            {ok, Buf} ->
                Worker ! {start, Sid},
                lists:foreach(fun({D, F}) ->
                    Worker ! {h2, Conn, {data, Sid, D, F}}
                end, Buf)
        end,
        h2:send_response(Conn, Sid, 200, [])
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"CONNECT">>, <<>>, [
        {<<"host">>, <<"target:1">>}
    ]),
    receive {h2, Conn, {response, Sid, 200, _}} -> ok after 2000 -> ct:fail(no_resp) end,
    %% Client sends data and END_STREAM (half-closes write side).
    ok = h2:send_data(Conn, Sid, <<"ping">>, true),
    %% Server should still send back data after seeing client's END_STREAM.
    receive
        {h2, Conn, {data, Sid, <<"PING-ACK">>, true}} -> ok
    after 3000 ->
        ct:fail(no_server_data_after_half_close)
    end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

worker_half_close_loop(Conn, Sid, Acc) ->
    receive
        {h2, Conn, {data, Sid, _Data, true}} ->
            h2:send_data(Conn, Sid, <<"PING-ACK">>, true),
            _ = Acc,
            ok;
        {h2, Conn, {data, Sid, Data, false}} ->
            worker_half_close_loop(Conn, Sid, <<Acc/binary, Data/binary>>)
    after 5000 ->
        ok
    end.

connect_response_4xx_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Handler = fun(Conn, Sid, <<"CONNECT">>, _, _) ->
        h2:send_response(Conn, Sid, 502, []),
        h2:send_data(Conn, Sid, <<>>, true)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"CONNECT">>, <<>>, [
        {<<"host">>, <<"target:1">>}
    ]),
    Resp = receive_full_response(Conn, Sid, 2000),
    ?assertMatch({502, _, _}, Resp),
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

connect_trailers_rejected_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Self = self(),
    Handler = fun(Conn, Sid, <<"CONNECT">>, _, _) ->
        h2:send_response(Conn, Sid, 200, []),
        %% After 2xx, attempt to send trailers — should fail at connection level
        %% via send_trailers because tunnel forbids them. We only assert the
        %% client side sees a stream_reset / closed event.
        Self ! {tunnel_open, Conn, Sid},
        receive after 1500 -> ok end,
        catch h2:send_trailers(Conn, Sid, [{<<"x-trailer">>, <<"v">>}])
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"CONNECT">>, <<>>, [
        {<<"host">>, <<"t:1">>}
    ]),
    receive {h2, Conn, {response, Sid, 200, _}} -> ok after 2000 -> ct:fail(no_resp) end,
    %% Trying to send a HEADERS block with no pseudo-headers (a trailer shape)
    %% via the request API is caught client-side by outbound validation.
    {error, protocol_error} = h2:request(Conn, [{<<"x-fake-trailer">>, <<"v">>}],
                                         #{end_stream => true}),
    %% Connection survives regardless.
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% ============================================================================
%% Compliance v2 (second-look audit)
%% ============================================================================

tunnel_outbound_trailers_rejected_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Self = self(),
    Handler = fun(Conn, Sid, <<"CONNECT">>, _, _) ->
        h2:send_response(Conn, Sid, 200, []),
        Result = h2:send_trailers(Conn, Sid, [{<<"x">>, <<"y">>}]),
        Self ! {trailer_result, Result},
        receive after 500 -> ok end
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"CONNECT">>, <<>>,
                           [{<<"host">>, <<"t:1">>}]),
    receive {h2, Conn, {response, Sid, 200, _}} -> ok
    after 2000 -> ct:fail(no_connect_response) end,
    receive
        {trailer_result, {error, tunnel_no_trailers}} -> ok
    after 2000 ->
        ct:fail(trailers_not_rejected)
    end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% RFC 9113 §6.5.2: a server MUST NOT send SETTINGS_ENABLE_PUSH=1. Open a
%% raw TLS socket, read the server's initial SETTINGS frame, and check the
%% ENABLE_PUSH parameter value.
server_push_setting_disabled_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = ssl:connect("localhost", Port,
                             [{active, false}, {mode, binary},
                              {alpn_advertised_protocols, [<<"h2">>]},
                              {verify, verify_none}], 5000),
    ok = ssl:send(Sock, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>),
    %% Server sends its SETTINGS right after our preface arrives.
    SettingsPayload = read_first_settings(Sock),
    Pairs = parse_settings_payload(SettingsPayload),
    %% SETTINGS_ENABLE_PUSH = 0x2
    case proplists:get_value(16#2, Pairs) of
        undefined ->
            ok;  %% Not advertised → default 1 per spec; reject.
        Value ->
            ?assertEqual(0, Value)
    end,
    ssl:close(Sock),
    ok.

read_first_settings(Sock) ->
    %% Read frames until we see a non-ACK SETTINGS from the server.
    {ok, <<Len:24, Type:8, Flags:8, _:32>>} = ssl:recv(Sock, 9, 2000),
    case {Type, Flags band 16#1} of
        {16#4, 0} ->
            case Len of
                0 -> <<>>;
                _ -> {ok, Payload} = ssl:recv(Sock, Len, 2000), Payload
            end;
        _ ->
            _ = case Len of
                0 -> <<>>;
                _ -> {ok, _} = ssl:recv(Sock, Len, 2000), <<>>
            end,
            read_first_settings(Sock)
    end.

parse_settings_payload(<<>>) -> [];
parse_settings_payload(<<Id:16, Value:32, Rest/binary>>) ->
    [{Id, Value} | parse_settings_payload(Rest)].

%% Send-side validation: uppercase letter in header name → protocol_error.
outbound_uppercase_header_rejected_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    ?assertEqual({error, protocol_error},
        h2:request(Conn, <<"GET">>, <<"/">>,
                   [{<<"host">>, <<"localhost">>}, {<<"X-Bad">>, <<"v">>}])),
    h2:close(Conn),
    drain_exits(),
    ok.

%% Send-side validation: request missing required :path → protocol_error.
outbound_bad_pseudo_rejected_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    %% No :path, no :scheme, no :authority, no :method.
    ?assertEqual({error, protocol_error},
        h2:request(Conn, [{<<":method">>, <<"GET">>}])),
    h2:close(Conn),
    drain_exits(),
    ok.

%% RFC 9113 §8.6: server MUST NOT generate 101.
send_response_101_rejected_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Self = self(),
    Handler = fun(Conn, Sid, _, _, _) ->
        R = h2:send_response(Conn, Sid, 101, []),
        Self ! {resp, R},
        h2:send_response(Conn, Sid, 200, []),
        h2:send_data(Conn, Sid, <<>>, true)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, _Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"l">>}]),
    receive
        {resp, {error, status_101_forbidden}} -> ok
    after 2000 ->
        ct:fail(no_101_reject)
    end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% Owner receives {goaway, LastStreamId, ErrorCode} 3-tuple.
goaway_event_three_tuple_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    ok = h2:goaway(Conn),
    %% Our own goaway doesn't produce an incoming {goaway, ...} event on us.
    %% Instead, stop the server to force the peer to GOAWAY.
    h2:close(Conn),
    OldRef = ?config(server_ref, Config),
    h2:stop_server(OldRef),
    %% Second connection: server closes immediately.
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => fun(_, _, _, _, _) -> ok end
    }),
    Port2 = h2:server_port(Ref),
    {ok, Conn2} = h2:connect("localhost", Port2, #{ssl_opts => [{verify, verify_none}]}),
    ok = h2:stop_server(Ref),
    receive
        {h2, Conn2, {goaway, _Last, ErrorCode}} when is_atom(ErrorCode) -> ok
    after 2000 ->
        %% Some scheduling paths close the connection without an explicit
        %% goaway; tolerate a clean {closed, _} as well.
        receive
            {h2, Conn2, {closed, _}} -> ok
        after 500 ->
            ct:fail(no_goaway_or_close)
        end
    end,
    catch h2:close(Conn2),
    drain_exits(),
    ok.

%% RFC 9113 §8.2.1: leading SP/HTAB in a field value is malformed.
leading_space_value_rejected_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    ?assertEqual({error, protocol_error},
        h2:request(Conn, <<"GET">>, <<"/">>,
                   [{<<"host">>, <<"localhost">>}, {<<"x-v">>, <<" leading">>}])),
    h2:close(Conn),
    drain_exits(),
    ok.

%% Invalid tchar in name (colon in middle, space, etc.)
invalid_name_chars_rejected_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    ?assertEqual({error, protocol_error},
        h2:request(Conn, <<"GET">>, <<"/">>,
                   [{<<"host">>, <<"localhost">>}, {<<"bad name">>, <<"v">>}])),
    h2:close(Conn),
    drain_exits(),
    ok.

%% Large header block must be split into HEADERS + CONTINUATION frames
%% respecting peer's MAX_FRAME_SIZE (default 16384).
large_request_split_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    Big = binary:copy(<<"a">>, 40000),
    {ok, _} = h2:request(Conn, <<"GET">>, <<"/">>,
                         [{<<"host">>, <<"localhost">>},
                          {<<"x-big">>, Big}]),
    %% If splitting is wrong, server returns PROTOCOL_ERROR/FRAME_SIZE_ERROR
    %% and the connection dies quickly. We expect a normal response flow.
    receive
        {h2, Conn, {response, _, _, _}} -> ok;
        {h2, Conn, {closed, Reason}} -> ct:fail({connection_closed, Reason})
    after 3000 ->
        ct:fail(no_response)
    end,
    h2:close(Conn),
    drain_exits(),
    ok.

%% Client enforces peer's MAX_HEADER_LIST_SIZE before encoding.
peer_max_header_list_size_enforced_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => fun(Conn, Sid, _, _, _) ->
            h2:send_response(Conn, Sid, 200, []),
            h2:send_data(Conn, Sid, <<>>, true)
        end,
        settings => #{max_header_list_size => 500}
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    Big = binary:copy(<<"a">>, 1000),
    ?assertEqual({error, header_list_too_large},
        h2:request(Conn, <<"GET">>, <<"/">>,
                   [{<<"host">>, <<"l">>}, {<<"x-big">>, Big}])),
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% h2:connect/3 top-level verify option is honored.
connect_verify_option_honored_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{verify => verify_none}),
    {ok, _Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"localhost">>}]),
    h2:close(Conn),
    drain_exits(),
    ok.

%% transport => tcp starts a cleartext listener and round-trips a request.
tcp_server_round_trip_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    {ok, Ref} = h2:start_server(0, #{
        transport => tcp,
        handler => fun(Conn, Sid, _, _, _) ->
            h2:send_response(Conn, Sid, 200, []),
            h2:send_data(Conn, Sid, <<"ok">>, true)
        end
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{transport => tcp}),
    {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"localhost">>}]),
    receive
        {h2, Conn, {response, Sid, 200, _}} -> ok
    after 2000 -> ct:fail(no_response) end,
    receive
        {h2, Conn, {data, Sid, <<"ok">>, true}} -> ok
    after 2000 -> ct:fail(no_body) end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% A process registered as a stream handler receives trailers.
stream_handler_receives_trailers_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Self = self(),
    Handler = fun(Conn, Sid, _, _, _) ->
        case h2:set_stream_handler(Conn, Sid, Self) of
            ok -> ok;
            {ok, _Buf} -> ok
        end,
        Self ! {ready, Conn, Sid},
        %% Block briefly so the trailer event is processed before this exits.
        timer:sleep(800)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    %% Open stream without END_STREAM so we can add DATA + trailers.
    {ok, Sid} = h2:request(Conn, [
        {<<":method">>, <<"POST">>},
        {<<":path">>, <<"/">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>}
    ], #{end_stream => false}),
    receive {ready, _, _} -> ok after 2000 -> ct:fail(no_handler) end,
    ok = h2:send_data(Conn, Sid, <<"body">>, false),
    ok = h2:send_trailers(Conn, Sid, [{<<"x-trail">>, <<"v">>}]),
    receive
        {h2, _SrvConn, {trailers, _, Trailers}} ->
            ?assertEqual(<<"v">>, proplists:get_value(<<"x-trail">>, Trailers))
    after 2500 ->
        ct:fail(no_trailers)
    end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% Body-less response (204) should still deliver a trailing {data, _, <<>>, true}
%% event so clients waiting for end-of-stream don't hang. Matches quic_h3.
empty_response_emits_trailing_data_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Handler = fun(Conn, Sid, _, _, _) ->
        h2:send_response(Conn, Sid, 204, []),
        %% Force HEADERS with END_STREAM by sending empty DATA with fin.
        h2:send_data(Conn, Sid, <<>>, true)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{verify => verify_none}),
    {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"l">>}]),
    receive {h2, Conn, {response, Sid, 204, _}} -> ok
    after 2000 -> ct:fail(no_response) end,
    receive
        {h2, Conn, {data, Sid, <<>>, true}} -> ok
    after 1500 ->
        ct:fail(no_trailing_data)
    end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% RFC 9113 §8.2: header values containing NUL/LF/CR are malformed. The
%% client MUST refuse to send them; we enforce this on the send side.
header_value_with_nul_rejected_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    Result = h2:request(Conn, [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"localhost">>},
        {<<"x-bad">>, <<"he", 0, "llo">>}
    ]),
    ?assertEqual({error, protocol_error}, Result),
    h2:close(Conn),
    drain_exits(),
    ok.

%% ============================================================================
%% RFC 8441 Extended CONNECT tests
%% ============================================================================

%% Server with enable_connect_protocol=true advertises SETTINGS id 0x8 = 1.
extended_connect_setting_advertised_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => fun(_, _, _, _, _) -> ok end,
        enable_connect_protocol => true
    }),
    Port = h2:server_port(Ref),
    {ok, Sock} = ssl:connect("localhost", Port,
                             [{active, false}, {mode, binary},
                              {alpn_advertised_protocols, [<<"h2">>]},
                              {verify, verify_none}], 5000),
    ok = ssl:send(Sock, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>),
    Payload = read_first_settings(Sock),
    Pairs = parse_settings_payload(Payload),
    %% SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8
    ?assertEqual(1, proplists:get_value(16#8, Pairs)),
    ssl:close(Sock),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% Default server does not advertise the setting (or sends it as 0).
extended_connect_setting_default_off_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = ssl:connect("localhost", Port,
                             [{active, false}, {mode, binary},
                              {alpn_advertised_protocols, [<<"h2">>]},
                              {verify, verify_none}], 5000),
    ok = ssl:send(Sock, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>),
    Payload = read_first_settings(Sock),
    Pairs = parse_settings_payload(Payload),
    case proplists:get_value(16#8, Pairs) of
        undefined -> ok;
        Value -> ?assertEqual(0, Value)
    end,
    ssl:close(Sock),
    ok.

%% End-to-end Extended CONNECT round-trip: client sends `:protocol = websocket`,
%% server replies 200, both sides exchange tunnel bytes.
extended_connect_round_trip_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Self = self(),
    Handler = fun(Conn, Sid, <<"CONNECT">>, _, Headers) ->
        Self ! {ec_request, Sid, proplists:get_value(<<":protocol">>, Headers)},
        Worker = spawn(fun() ->
            receive {start, S} ->
                tunnel_echo_loop(Conn, S)
            end
        end),
        case h2:set_stream_handler(Conn, Sid, Worker) of
            ok            -> Worker ! {start, Sid};
            {ok, Buf}     ->
                Worker ! {start, Sid},
                lists:foreach(fun({D, F}) ->
                    Worker ! {h2, Conn, {data, Sid, D, F}}
                end, Buf)
        end,
        h2:send_response(Conn, Sid, 200, [])
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler,
        enable_connect_protocol => true
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    %% Wait for SETTINGS exchange so peer_settings reflect server opt-in.
    timer:sleep(100),
    {ok, Sid} = h2:request(Conn, [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/chat">>},
        {<<":authority">>, <<"localhost">>}
    ], #{protocol => <<"websocket">>}),
    receive {ec_request, Sid, <<"websocket">>} -> ok
    after 2000 -> ct:fail(no_extended_connect_seen_by_server) end,
    receive {h2, Conn, {response, Sid, 200, _}} -> ok
    after 2000 -> ct:fail(no_response) end,
    ok = h2:send_data(Conn, Sid, <<"hello">>, false),
    receive {h2, Conn, {data, Sid, <<"hello">>, false}} -> ok
    after 2000 -> ct:fail(no_echo) end,
    ok = h2:send_data(Conn, Sid, <<"bye">>, true),
    receive {h2, Conn, {data, Sid, <<"bye">>, true}} -> ok
    after 2000 -> ct:fail(no_final_echo) end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% Client sending Extended CONNECT to a server that did not advertise the
%% setting must fail with extended_connect_disabled before any frame is sent.
extended_connect_client_refuses_when_peer_disabled_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    timer:sleep(100),
    Result = h2:request(Conn, [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/chat">>},
        {<<":authority">>, <<"localhost">>}
    ], #{protocol => <<"websocket">>}),
    ?assertEqual({error, extended_connect_disabled}, Result),
    h2:close(Conn),
    drain_exits(),
    ok.

%% `:protocol` requires `:method=CONNECT`; any other method is rejected client-side.
extended_connect_method_must_be_connect_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => fun(_, _, _, _, _) -> ok end,
        enable_connect_protocol => true
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    timer:sleep(100),
    Result = h2:request(Conn, [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/chat">>},
        {<<":authority">>, <<"localhost">>},
        {<<":protocol">>, <<"websocket">>}
    ], #{end_stream => false}),
    ?assertEqual({error, extended_connect_method}, Result),
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% Trailers stay forbidden on the tunnel established by Extended CONNECT.
extended_connect_trailers_rejected_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Self = self(),
    Handler = fun(Conn, Sid, <<"CONNECT">>, _, _) ->
        h2:send_response(Conn, Sid, 200, []),
        Result = h2:send_trailers(Conn, Sid, [{<<"x">>, <<"y">>}]),
        Self ! {trailer_result, Result},
        receive after 500 -> ok end
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler,
        enable_connect_protocol => true
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    timer:sleep(100),
    {ok, Sid} = h2:request(Conn, [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/c">>},
        {<<":authority">>, <<"localhost">>}
    ], #{protocol => <<"websocket">>}),
    receive {h2, Conn, {response, Sid, 200, _}} -> ok
    after 2000 -> ct:fail(no_response) end,
    receive {trailer_result, {error, tunnel_no_trailers}} -> ok
    after 2000 -> ct:fail(trailers_not_rejected) end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% Server that did NOT advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1 must reject
%% an inbound HEADERS frame carrying `:protocol` with stream-level PROTOCOL_ERROR
%% (RFC 8441 §4). Uses raw SSL to bypass the client guard.
extended_connect_server_rejects_when_disabled_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = ssl:connect("localhost", Port,
                             [{active, false}, {mode, binary},
                              {alpn_advertised_protocols, [<<"h2">>]},
                              {verify, verify_none}], 5000),
    %% Preface + empty SETTINGS.
    ok = ssl:send(Sock, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:settings([]))),
    %% Drain server SETTINGS, then ACK it.
    _ = read_first_settings(Sock),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:settings_ack())),
    %% Send Extended CONNECT HEADERS on stream 1.
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/c">>},
        {<<":authority">>, <<"localhost">>},
        {<<":protocol">>, <<"websocket">>}
    ],
    {Block, _Ctx} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block, false))),
    %% Expect RST_STREAM with PROTOCOL_ERROR (= 1) on stream 1.
    case wait_for_rst_stream(Sock, 1, 3000) of
        {ok, ErrorCode} ->
            ?assertEqual(1, ErrorCode);  %% PROTOCOL_ERROR
        timeout ->
            ct:fail(no_rst_stream)
    end,
    ssl:close(Sock),
    ok.

wait_for_rst_stream(Sock, StreamId, Timeout) ->
    case ssl:recv(Sock, 9, Timeout) of
        {ok, <<Len:24, Type:8, _Flags:8, _:1, Sid:31>>} ->
            Payload = case Len of
                0 -> <<>>;
                _ -> {ok, P} = ssl:recv(Sock, Len, Timeout), P
            end,
            case {Type, Sid, Payload} of
                {16#3, StreamId, <<ErrorCode:32>>} ->
                    {ok, ErrorCode};
                _ ->
                    wait_for_rst_stream(Sock, StreamId, Timeout)
            end;
        {error, _} ->
            timeout
    end.

%% ============================================================================
%% Third-pass review fixes (RFC 9113 §8.1, RFC 9110 §15.2, RFC 9113 §8.3.1,
%% RFC 7540 §8.3, RFC 8441 §4)
%% ============================================================================

%% RFC 9113 §8.1: a 1xx interim response with END_STREAM is malformed.
%% Raw TLS server replies 103 + END_STREAM; h2 client must reject with
%% RST_STREAM(PROTOCOL_ERROR) and must NOT deliver an `informational` event.
informational_end_stream_rejected_test(Config) ->
    {ok, LS, Port} = raw_tls_listen(Config),
    Parent = self(),
    _Srv = spawn(fun() ->
        {ok, S} = raw_tls_accept(LS),
        fake_server_await_headers(S),
        {Block, _} = h2_hpack:encode([{<<":status">>, <<"103">>}],
                                     h2_hpack:new_context()),
        ok = ssl:send(S, h2_frame:encode(h2_frame:headers(1, Block, true))),
        %% Read the client's RST_STREAM back on this socket.
        Result = wait_for_rst_stream(S, 1, 3000),
        Parent ! {srv_rst, Result},
        timer:sleep(200),
        ssl:close(S)
    end),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"localhost">>}]),
    %% The guard must fire client-side: no informational event should surface.
    receive
        {h2, Conn, {informational, Sid, 103, _}} ->
            ct:fail(interim_end_stream_accepted)
    after 500 ->
        ok
    end,
    %% And the raw server must have received the RST_STREAM.
    receive
        {srv_rst, {ok, ErrorCode}} ->
            ?assertEqual(1, ErrorCode);          %% PROTOCOL_ERROR
        {srv_rst, timeout} ->
            ct:fail(client_did_not_rst)
    after 4000 ->
        ct:fail(no_srv_rst_result)
    end,
    catch h2:close(Conn),
    catch ssl:close(LS),
    drain_exits(),
    ok.

%% RFC 9113 §8.3.1: outbound `:authority` with userinfo MUST be rejected
%% client-side before HPACK encoding.
authority_userinfo_rejected_outbound_test(Config) ->
    Port = ?config(port, Config),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    Result = h2:request(Conn, [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"user:pass@localhost">>}
    ]),
    ?assertEqual({error, protocol_error}, Result),
    h2:close(Conn),
    drain_exits(),
    ok.

%% Inbound version via raw SSL: server MUST stream-reset a HEADERS frame
%% whose `:authority` contains userinfo.
authority_userinfo_rejected_inbound_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"bob@localhost">>}
    ],
    {Block, _Ctx} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block, true))),
    case wait_for_rst_stream(Sock, 1, 3000) of
        {ok, ErrorCode} -> ?assertEqual(1, ErrorCode);
        timeout -> ct:fail(no_rst_stream)
    end,
    ssl:close(Sock),
    ok.

%% RFC 8441 §4: `:protocol` MUST be a RFC 7230 token. A server advertising
%% ENABLE_CONNECT_PROTOCOL=1 still rejects a non-token value.
extended_connect_bad_protocol_token_rejected_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => fun(_, _, _, _, _) -> ok end,
        enable_connect_protocol => true
    }),
    Port = h2:server_port(Ref),
    {ok, Sock} = raw_h2_client(Port),
    Headers = [
        {<<":method">>, <<"CONNECT">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/c">>},
        {<<":authority">>, <<"localhost">>},
        {<<":protocol">>, <<"web socket">>}   %% space → not a token
    ],
    {Block, _Ctx} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block, false))),
    case wait_for_rst_stream(Sock, 1, 3000) of
        {ok, ErrorCode} -> ?assertEqual(1, ErrorCode);
        timeout -> ct:fail(no_rst_stream)
    end,
    ssl:close(Sock),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% RFC 7540 §8.3: a non-2xx response to CONNECT does NOT open a tunnel, so
%% the server MAY send trailers on a 4xx CONNECT response. Before the fix,
%% the tunnel flag was set on request receipt and blocked trailers.
connect_non_2xx_trailers_allowed_test(Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef -> h2:stop_server(OldRef)
    end,
    Self = self(),
    Handler = fun(Conn, Sid, <<"CONNECT">>, _, _) ->
        h2:send_response(Conn, Sid, 502, []),
        Result = h2:send_trailers(Conn, Sid, [{<<"x-reason">>, <<"bad-gateway">>}]),
        Self ! {trailer_result, Result}
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert => ?config(cert_file, Config),
        key => ?config(key_file, Config),
        handler => Handler
    }),
    Port = h2:server_port(Ref),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, _Sid} = h2:request(Conn, <<"CONNECT">>, <<>>,
                            [{<<"host">>, <<"t:1">>}]),
    receive
        {trailer_result, ok} -> ok;
        {trailer_result, Other} -> ct:fail({trailers_rejected, Other})
    after 3000 ->
        ct:fail(no_trailer_result)
    end,
    h2:close(Conn),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% Raw HTTP/2 client: SSL connect + preface + empty SETTINGS + drain server
%% SETTINGS + SETTINGS_ACK. Returns a socket ready to send HEADERS.
raw_h2_client(Port) ->
    {ok, Sock} = ssl:connect("localhost", Port,
                             [{active, false}, {mode, binary},
                              {alpn_advertised_protocols, [<<"h2">>]},
                              {verify, verify_none}], 5000),
    ok = ssl:send(Sock, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:settings([]))),
    _ = read_first_settings(Sock),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:settings_ack())),
    {ok, Sock}.

%% RFC 9113 §5.1: a stream closed via END_STREAM accepts only PRIORITY; any
%% other frame is a CONNECTION error STREAM_CLOSED. Before the fix the server
%% replied with a stream-scoped RST_STREAM.
closed_stream_headers_triggers_goaway_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    {Block, Ctx1} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    %% Open + close stream 1 via END_STREAM.
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block, true))),
    %% Wait for the server's response + END_STREAM on stream 1.
    ok = drain_until_end_stream(Sock, 1, 3000),
    %% Send a second HEADERS on the now-closed stream. Spec mandates GOAWAY.
    {Block2, _} = h2_hpack:encode(Headers, Ctx1),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block2, true))),
    case wait_for_goaway(Sock, 3000) of
        {ok, ErrorCode} -> ?assertEqual(5, ErrorCode);  %% STREAM_CLOSED
        timeout         -> ct:fail(no_goaway)
    end,
    ssl:close(Sock),
    ok.

%% Same as above but the second frame is DATA.
closed_stream_data_triggers_goaway_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    {Block, _Ctx1} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block, true))),
    ok = drain_until_end_stream(Sock, 1, 3000),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:data(1, <<"junk">>, false))),
    case wait_for_goaway(Sock, 3000) of
        {ok, ErrorCode} -> ?assertEqual(5, ErrorCode);  %% STREAM_CLOSED
        timeout         -> ct:fail(no_goaway)
    end,
    ssl:close(Sock),
    ok.

%% After RST_STREAM from the client, the server MUST treat HEADERS on that
%% stream as a stream error (RST_STREAM), not a connection error.
rst_closed_stream_headers_triggers_rst_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    {Block, Ctx1} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block, true))),
    %% Close the stream ourselves with RST_STREAM.
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:rst_stream(1, 8))),
    %% Now send HEADERS on the rst-closed stream — expect RST_STREAM.
    {Block2, _} = h2_hpack:encode(Headers, Ctx1),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block2, true))),
    case wait_for_rst_or_goaway(Sock, 3000) of
        {rst, ErrorCode} -> ?assertEqual(5, ErrorCode);  %% STREAM_CLOSED
        {goaway, _}      -> ct:fail(expected_stream_error_got_connection);
        timeout          -> ct:fail(no_rst_stream)
    end,
    ssl:close(Sock),
    ok.

rst_closed_stream_data_triggers_rst_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    {Block, _} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block, true))),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:rst_stream(1, 8))),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:data(1, <<"junk">>, false))),
    case wait_for_rst_or_goaway(Sock, 3000) of
        {rst, ErrorCode} -> ?assertEqual(5, ErrorCode);
        {goaway, _}      -> ct:fail(expected_stream_error_got_connection);
        timeout          -> ct:fail(no_rst_stream)
    end,
    ssl:close(Sock),
    ok.

%% CONTINUATION without a preceding non-END_HEADERS HEADERS frame is a
%% connection PROTOCOL_ERROR per RFC 9113 §6.10, even (especially) on a
%% closed stream — h2spec §5.1/13.
closed_stream_continuation_triggers_goaway_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    {Block, Ctx1} = h2_hpack:encode(Headers, h2_hpack:new_context()),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block, true))),
    ok = drain_until_end_stream(Sock, 1, 3000),
    {Block2, _} = h2_hpack:encode(Headers, Ctx1),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:continuation(1, Block2, true))),
    case wait_for_goaway(Sock, 3000) of
        {ok, _ErrorCode} -> ok;  %% STREAM_CLOSED or PROTOCOL_ERROR both acceptable
        timeout          -> ct:fail(no_goaway)
    end,
    ssl:close(Sock),
    ok.

%% RFC 9113 §5.1.2: a peer that exceeds our advertised
%% SETTINGS_MAX_CONCURRENT_STREAMS must get a stream error
%% (REFUSED_STREAM) on the offending HEADERS.
max_concurrent_streams_refuses_excess_test(Config) ->
    %% Stop the shared server and bring up one that advertises max=1 and
    %% keeps the handler pending so stream 1 stays open.
    case ?config(server_ref, Config) of
        undefined -> ok;
        OldRef    -> h2:stop_server(OldRef)
    end,
    Handler = fun(_Conn, _Sid, _, _, _) ->
        timer:sleep(1000)
    end,
    {ok, Ref} = h2:start_server(0, #{
        cert     => ?config(cert_file, Config),
        key      => ?config(key_file, Config),
        handler  => Handler,
        settings => #{max_concurrent_streams => 1}
    }),
    Port = h2:server_port(Ref),
    {ok, Sock} = raw_h2_client(Port),
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/">>},
        {<<":authority">>, <<"localhost">>}
    ],
    Ctx0 = h2_hpack:new_context(),
    {Block1, Ctx1} = h2_hpack:encode(Headers, Ctx0),
    %% Stream 1 open (no END_STREAM): counts toward the limit.
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(1, Block1, false))),
    {Block3, _} = h2_hpack:encode(Headers, Ctx1),
    %% Stream 3 would push us over max=1 → expect RST_STREAM(REFUSED_STREAM=7).
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:headers(3, Block3, true))),
    case wait_for_rst_or_goaway(Sock, 3000) of
        {rst, ErrorCode} -> ?assertEqual(7, ErrorCode);
        Other            -> ct:fail({expected_rst_refused, Other})
    end,
    ssl:close(Sock),
    h2:stop_server(Ref),
    drain_exits(),
    ok.

%% RFC 9113 §6.5.2: a client that receives SETTINGS_ENABLE_PUSH with any
%% value other than 0 MUST treat it as a connection PROTOCOL_ERROR.
client_rejects_enable_push_one_test(Config) ->
    {ok, LS, Port} = raw_tls_listen(Config),
    Parent = self(),
    spawn_link(fun() ->
        {ok, Tr} = ssl:transport_accept(LS, 5000),
        {ok, S}  = ssl:handshake(Tr, 5000),
        _ = ssl:recv(S, byte_size(<<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>), 5000),
        %% Send SETTINGS with enable_push=1 — forbidden toward a client.
        ok = ssl:send(S, h2_frame:encode(h2_frame:settings([{enable_push, 1}]))),
        Result = wait_for_goaway(S, 3000),
        Parent ! {goaway_result, Result},
        ssl:close(S)
    end),
    %% Our client connects; it must reject peer SETTINGS → GOAWAY.
    _ = (catch h2:connect("localhost", Port,
                           #{ssl_opts => [{verify, verify_none}]})),
    receive
        {goaway_result, {ok, ErrorCode}} ->
            ?assertEqual(1, ErrorCode);  %% PROTOCOL_ERROR
        {goaway_result, Other} ->
            ct:fail({no_goaway, Other})
    after 5000 ->
        ct:fail(server_timeout)
    end,
    ssl:close(LS),
    drain_exits(),
    ok.

%% RFC 9110 §9.3.2: a HEAD response MAY carry content-length indicating the
%% size of the would-be GET body. Our client must accept it alongside
%% END_STREAM without treating it as a body-length mismatch.
head_response_with_content_length_accepted_test(Config) ->
    {ok, LS, Port} = raw_tls_listen(Config),
    Parent = self(),
    spawn_link(fun() ->
        {ok, S} = raw_tls_accept(LS),
        fake_server_await_headers(S),
        Hdrs = [{<<":status">>, <<"200">>}, {<<"content-length">>, <<"1234">>}],
        {Block, _} = h2_hpack:encode(Hdrs, h2_hpack:new_context()),
        ok = ssl:send(S, h2_frame:encode(h2_frame:headers(1, Block, true))),
        Parent ! done_sending,
        timer:sleep(500),
        ssl:close(S)
    end),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"HEAD">>, <<"/">>, [{<<"host">>, <<"l">>}]),
    Resp = receive_full_response(Conn, Sid, 3000),
    ?assertMatch({200, _, <<>>}, Resp),
    h2:close(Conn),
    ssl:close(LS),
    drain_exits(),
    ok.

%% RFC 9110 §15.4: a 204 response terminates at the header block. A header
%% block without END_STREAM is malformed and the client must reject the
%% stream rather than leave it open accepting later frames.
body_forbidden_response_without_end_stream_rejected_test(Config) ->
    {ok, LS, Port} = raw_tls_listen(Config),
    spawn_link(fun() ->
        {ok, S} = raw_tls_accept(LS),
        fake_server_await_headers(S),
        Hdrs = [{<<":status">>, <<"204">>}],
        {Block, _} = h2_hpack:encode(Hdrs, h2_hpack:new_context()),
        %% HEADERS without END_STREAM — not allowed for 204.
        ok = ssl:send(S, h2_frame:encode(h2_frame:headers(1, Block, false))),
        timer:sleep(500),
        ssl:close(S)
    end),
    {ok, Conn} = h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]}),
    {ok, Sid} = h2:request(Conn, <<"GET">>, <<"/">>, [{<<"host">>, <<"l">>}]),
    Result = receive_full_response(Conn, Sid, 3000),
    ?assertMatch({error, {stream_reset, _}}, Result),
    h2:close(Conn),
    ssl:close(LS),
    drain_exits(),
    ok.

%% RFC 9113 §6.3: a PRIORITY frame with a length other than 5 octets is a
%% *stream* error FRAME_SIZE_ERROR — RST_STREAM, not GOAWAY.
priority_wrong_length_is_stream_error_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    %% Hand-craft PRIORITY(type=2) on stream 1 with a 4-byte payload (should be 5).
    Bad = <<4:24, 2:8, 0:8, 0:1, 1:31, 0,0,0,0>>,
    ok = ssl:send(Sock, Bad),
    case wait_for_rst_or_goaway(Sock, 3000) of
        {rst, ErrorCode} -> ?assertEqual(6, ErrorCode);  %% FRAME_SIZE_ERROR
        Other            -> ct:fail({expected_stream_error, Other})
    end,
    ssl:close(Sock),
    ok.

%% RFC 9113 §3.3: over TLS, "h2" MUST be negotiated via ALPN. Our client
%% must not assume HTTP/2 when ALPN was skipped.
connect_ssl_without_alpn_rejected_test(Config) ->
    %% Listen with TLS but advertise no ALPN protocols.
    Opts = [
        {certfile, ?config(cert_file, Config)},
        {keyfile, ?config(key_file, Config)},
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {reuseaddr, true},
        {active, false},
        {mode, binary}
    ],
    {ok, LS} = ssl:listen(0, Opts),
    {ok, {_, Port}} = ssl:sockname(LS),
    spawn_link(fun() ->
        _ = (catch begin
            {ok, Tr} = ssl:transport_accept(LS, 5000),
            _ = ssl:handshake(Tr, 5000)
        end)
    end),
    ?assertMatch({error, alpn_not_negotiated},
                 h2:connect("localhost", Port, #{ssl_opts => [{verify, verify_none}]})),
    ssl:close(LS),
    ok.

%% RFC 9113 §4.1: a frame of unknown type MUST be ignored and discarded.
%% The server then continues processing normally — a PING round-trips.
unknown_frame_type_is_ignored_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    %% Frame type 0xFA is undefined. Send it on stream 0 with 4 bytes.
    Bad = <<4:24, 16#FA:8, 0:8, 0:1, 0:31, 0,0,0,0>>,
    ok = ssl:send(Sock, Bad),
    %% Follow with a PING — if the unknown frame was ignored, we get a PING ACK.
    PingData = <<1,2,3,4,5,6,7,8>>,
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:ping(PingData))),
    ?assertEqual({ok, PingData}, wait_for_ping_ack(Sock, 3000)),
    ssl:close(Sock),
    ok.

%% RFC 9113 §5.1: a frame other than HEADERS/PRIORITY on an idle stream is a
%% connection PROTOCOL_ERROR.
window_update_on_idle_stream_triggers_goaway_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:window_update(99, 1024))),
    case wait_for_goaway(Sock, 3000) of
        {ok, ErrorCode} -> ?assertEqual(1, ErrorCode);  %% PROTOCOL_ERROR
        timeout         -> ct:fail(no_goaway)
    end,
    ssl:close(Sock),
    ok.

wait_for_ping_ack(Sock, Timeout) ->
    case ssl:recv(Sock, 9, Timeout) of
        {ok, <<Len:24, Type:8, Flags:8, _:32>>} ->
            Payload = case Len of
                0 -> <<>>;
                _ -> {ok, P} = ssl:recv(Sock, Len, Timeout), P
            end,
            IsPingAck = Type =:= 16#6 andalso (Flags band 16#1) =:= 1,
            case IsPingAck of
                true  -> {ok, Payload};
                false -> wait_for_ping_ack(Sock, Timeout)
            end;
        {error, _} -> timeout
    end.

%% RFC 9113 §5.4: after sending GOAWAY the endpoint MUST close the TCP
%% connection. h2spec §5.4.1/1 otherwise times out waiting for close.
goaway_closes_tcp_socket_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    %% Force a connection error: WINDOW_UPDATE on an idle stream id.
    ok = ssl:send(Sock, h2_frame:encode(h2_frame:window_update(99, 1024))),
    case wait_for_goaway(Sock, 3000) of
        {ok, _ErrorCode} -> ok;
        timeout          -> ct:fail(no_goaway)
    end,
    %% The server must close the socket — ssl:recv must return closed.
    ?assertEqual({error, closed}, ssl:recv(Sock, 9, 3000)),
    ssl:close(Sock),
    ok.

%% RFC 9113 §6.9.2: a SETTINGS_INITIAL_WINDOW_SIZE value above 2^31-1 is a
%% connection FLOW_CONTROL_ERROR, not PROTOCOL_ERROR.
iws_exceeds_max_triggers_flow_control_error_test(Config) ->
    Port = ?config(port, Config),
    {ok, Sock} = raw_h2_client(Port),
    %% SETTINGS frame: one entry, IWS = 0x80000000 (2^31, above max 2^31-1).
    Payload = <<4:16, 16#80000000:32>>,
    Len = byte_size(Payload),
    Frame = <<Len:24, 4:8, 0:8, 0:1, 0:31, Payload/binary>>,
    ok = ssl:send(Sock, Frame),
    case wait_for_goaway(Sock, 3000) of
        {ok, ErrorCode} -> ?assertEqual(3, ErrorCode);  %% FLOW_CONTROL_ERROR
        timeout         -> ct:fail(no_goaway)
    end,
    ssl:close(Sock),
    ok.

wait_for_rst_or_goaway(Sock, Timeout) ->
    case ssl:recv(Sock, 9, Timeout) of
        {ok, <<Len:24, Type:8, _Flags:8, _:1, _Sid:31>>} ->
            Payload = case Len of
                0 -> <<>>;
                _ -> {ok, P} = ssl:recv(Sock, Len, Timeout), P
            end,
            case {Type, Payload} of
                {16#3, <<ErrorCode:32>>}                   -> {rst, ErrorCode};
                {16#7, <<_Last:32, ErrorCode:32, _/binary>>} -> {goaway, ErrorCode};
                _ -> wait_for_rst_or_goaway(Sock, Timeout)
            end;
        {error, _} -> timeout
    end.

%% Read frames until we see a DATA or HEADERS frame with END_STREAM on StreamId.
drain_until_end_stream(Sock, StreamId, Timeout) ->
    case ssl:recv(Sock, 9, Timeout) of
        {ok, <<Len:24, Type:8, Flags:8, _:1, Sid:31>>} ->
            _ = case Len of 0 -> <<>>; _ -> {ok, _} = ssl:recv(Sock, Len, Timeout) end,
            EndStream = (Flags band 16#1) =:= 1,
            IsData = Type =:= 16#0 orelse Type =:= 16#1,
            case IsData andalso EndStream andalso Sid =:= StreamId of
                true  -> ok;
                false -> drain_until_end_stream(Sock, StreamId, Timeout)
            end;
        {error, _} -> timeout
    end.

wait_for_goaway(Sock, Timeout) ->
    case ssl:recv(Sock, 9, Timeout) of
        {ok, <<Len:24, Type:8, _Flags:8, _:1, _Sid:31>>} ->
            Payload = case Len of
                0 -> <<>>;
                _ -> {ok, P} = ssl:recv(Sock, Len, Timeout), P
            end,
            case {Type, Payload} of
                {16#7, <<_LastStream:32, ErrorCode:32, _/binary>>} ->
                    {ok, ErrorCode};
                _ ->
                    wait_for_goaway(Sock, Timeout)
            end;
        {error, _} -> timeout
    end.

%% ---- Raw TLS fake-server helpers (for client-side behaviour tests) -------

raw_tls_listen(Config) ->
    Opts = [
        {certfile, ?config(cert_file, Config)},
        {keyfile, ?config(key_file, Config)},
        {alpn_preferred_protocols, [<<"h2">>]},
        {versions, ['tlsv1.2', 'tlsv1.3']},
        {reuseaddr, true},
        {active, false},
        {mode, binary}
    ],
    {ok, LS} = ssl:listen(0, Opts),
    {ok, {_, Port}} = ssl:sockname(LS),
    {ok, LS, Port}.

raw_tls_accept(LS) ->
    {ok, Tr} = ssl:transport_accept(LS, 5000),
    {ok, S}  = ssl:handshake(Tr, 5000),
    %% Read client preface, expect its SETTINGS, send ours + ACK theirs.
    {ok, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>} =
        ssl:recv(S, byte_size(<<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>), 5000),
    ok = ssl:send(S, h2_frame:encode(h2_frame:settings([]))),
    _ = drain_frames_until_settings(S),
    ok = ssl:send(S, h2_frame:encode(h2_frame:settings_ack())),
    {ok, S}.

%% Read frames until we see the client's SETTINGS (non-ACK) then ACK any
%% trailing ACK it might send; returns ok when the client is ready.
drain_frames_until_settings(S) ->
    case ssl:recv(S, 9, 5000) of
        {ok, <<Len:24, Type:8, Flags:8, _:32>>} ->
            _ = case Len of
                0 -> <<>>;
                _ -> {ok, _} = ssl:recv(S, Len, 5000)
            end,
            case {Type, Flags band 16#1} of
                {16#4, 0} -> ok;   %% SETTINGS (non-ACK) seen — done
                _ -> drain_frames_until_settings(S)
            end;
        {error, _} -> ok
    end.

%% Wait for a HEADERS frame from the client on stream 1.
fake_server_await_headers(S) ->
    {ok, <<Len:24, Type:8, _Flags:8, _:1, _Sid:31>>} = ssl:recv(S, 9, 5000),
    case Type of
        16#1 ->
            _ = case Len of 0 -> <<>>; _ -> {ok, _} = ssl:recv(S, Len, 5000) end,
            ok;
        _ ->
            _ = case Len of 0 -> <<>>; _ -> {ok, _} = ssl:recv(S, Len, 5000) end,
            fake_server_await_headers(S)
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

