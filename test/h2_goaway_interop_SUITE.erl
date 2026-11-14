%% @doc Graceful GOAWAY (RFC 9113 §6.8) against a real HTTP/2 client: curl,
%% built on nghttp2. The server calls `h2:goaway/1' while a request is in
%% flight; the response must still arrive whole, and a later request must go
%% to a new connection, never be lost or truncated. Also runs the reproduction
%% from issue #41 (h2 client and server over TLS).
%%
%% Needs curl with HTTP2 support (`curl -V' lists HTTP2); the curl cases skip
%% otherwise.
-module(h2_goaway_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-export([curl_tls_drain_test/1,
         curl_h2c_drain_test/1,
         curl_parallel_drain_test/1,
         curl_next_request_new_connection_test/1,
         h2_client_tls_drain_test/1]).

suite() ->
    [{timetrap, {seconds, 60}}].

all() ->
    [curl_tls_drain_test,
     curl_h2c_drain_test,
     curl_parallel_drain_test,
     curl_next_request_new_connection_test,
     h2_client_tls_drain_test].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(h2),
    {Cert, Key} = generate_test_certs(?config(priv_dir, Config)),
    [{cert_file, Cert}, {key_file, Key}, {curl, find_curl()} | Config].

end_per_suite(_Config) ->
    ok.

init_per_testcase(TC, Config) ->
    case {uses_curl(TC), ?config(curl, Config)} of
        {true, false} ->
            {skip, "curl with HTTP2 support not installed"};
        _ ->
            process_flag(trap_exit, true),
            Transport = case TC of
                curl_h2c_drain_test -> tcp;
                curl_parallel_drain_test -> tcp;
                curl_next_request_new_connection_test -> tcp;
                _ -> ssl
            end,
            Opts0 = #{handler => held_handler(self()), transport => Transport},
            Opts = case Transport of
                ssl -> Opts0#{cert => ?config(cert_file, Config),
                              key => ?config(key_file, Config)};
                tcp -> Opts0
            end,
            {ok, Ref} = h2:start_server(0, Opts),
            [{server_ref, Ref}, {port, h2:server_port(Ref)} | Config]
    end.

end_per_testcase(_TC, Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        Ref -> h2:stop_server(Ref)
    end,
    flush(),
    ok.

uses_curl(h2_client_tls_drain_test) -> false;
uses_curl(_) -> true.

%% ============================================================================
%% Tests
%% ============================================================================

%% The issue's scenario through curl over TLS (ALPN h2).
curl_tls_drain_test(Config) ->
    Url = url(https, Config, "/a"),
    Curl = start_curl(Config, ["-k", "--http2", Url]),
    {Conn, H} = wait_request(<<"/a">>),
    Mon = erlang:monitor(process, Conn),
    ok = h2:goaway(Conn),
    timer:sleep(300),
    H ! go,
    ?assertEqual({0, <<"done:/a">>}, wait_curl(Curl)),
    wait_down(Mon, Conn).

%% Same over prior-knowledge h2c.
curl_h2c_drain_test(Config) ->
    Url = url(http, Config, "/a"),
    Curl = start_curl(Config, ["--http2-prior-knowledge", Url]),
    {Conn, H} = wait_request(<<"/a">>),
    Mon = erlang:monitor(process, Conn),
    ok = h2:goaway(Conn),
    timer:sleep(300),
    H ! go,
    ?assertEqual({0, <<"done:/a">>}, wait_curl(Curl)),
    wait_down(Mon, Conn).

%% Two requests multiplexed on one connection, both in flight when the
%% GOAWAY goes out: both complete.
curl_parallel_drain_test(Config) ->
    Curl = start_curl(Config, ["--http2-prior-knowledge", "--parallel",
                               "--parallel-max", "2",
                               url(http, Config, "/a"), url(http, Config, "/b")]),
    {Conn, Ha} = wait_request(<<"/a">>),
    {Conn, Hb} = wait_request(<<"/b">>),
    ok = h2:goaway(Conn),
    timer:sleep(300),
    Ha ! go,
    Hb ! go,
    {0, Out} = wait_curl(Curl),
    ?assertEqual(lists:sort([<<"done:/a">>, <<"done:/b">>]),
                 lists:sort(binary:split(Out, <<"\n">>, [global, trim_all]))).

%% A request curl issues after seeing the GOAWAY goes to a new connection.
curl_next_request_new_connection_test(Config) ->
    Curl = start_curl(Config, ["--http2-prior-knowledge",
                               url(http, Config, "/a"), url(http, Config, "/b")]),
    {Conn, Ha} = wait_request(<<"/a">>),
    ok = h2:goaway(Conn),
    timer:sleep(300),
    Ha ! go,
    {Conn2, Hb} = wait_request(<<"/b">>),
    ?assertNotEqual(Conn, Conn2),
    Hb ! go,
    {0, Out} = wait_curl(Curl),
    ?assertEqual([<<"done:/a">>, <<"done:/b">>],
                 binary:split(Out, <<"\n">>, [global, trim_all])).

%% Issue #41 reproduction: h2 client and server over TLS, the server calls
%% goaway/1 while a request is running, the response still arrives.
h2_client_tls_drain_test(Config) ->
    {ok, Client} = h2:connect("localhost", ?config(port, Config),
                              #{ssl_opts => [{verify, verify_none}]}),
    ok = h2:wait_connected(Client),
    {ok, Sid} = h2:request(Client, <<"GET">>, <<"/a">>,
                           [{<<"host">>, <<"localhost">>}]),
    {Conn, H} = wait_request(<<"/a">>),
    ok = h2:goaway(Conn),
    timer:sleep(300),
    H ! go,
    ?assertEqual(<<"done:/a">>, client_body(Client, Sid, <<>>)),
    receive {h2, Client, {closed, _}} -> ok
    after 5000 -> ct:fail(client_not_closed)
    end.

%% ============================================================================
%% Helpers
%% ============================================================================

%% Reports each request, then answers `done:<path>' when told to.
held_handler(Test) ->
    fun(Conn, Sid, _Method, Path, _Headers) ->
            Test ! {request, Path, {Conn, self()}},
            receive go -> ok after 10000 -> ok end,
            ok = h2:send_response(Conn, Sid, 200, []),
            ok = h2:send_data(Conn, Sid, <<"done:", Path/binary, "\n">>, true)
    end.

wait_request(Path) ->
    receive {request, Path, {Conn, Pid}} -> {Conn, Pid}
    after 10000 -> ct:fail({no_request, Path})
    end.

wait_down(Mon, Conn) ->
    receive {'DOWN', Mon, process, Conn, Reason} ->
            ct:pal("server connection down: ~p", [Reason])
    after 5000 -> ct:fail(server_connection_not_closed)
    end.

client_body(Client, Sid, Acc) ->
    receive
        {h2, Client, {response, Sid, 200, _}} -> client_body(Client, Sid, Acc);
        {h2, Client, {data, Sid, D, true}} -> string:trim(<<Acc/binary, D/binary>>);
        {h2, Client, {data, Sid, D, false}} -> client_body(Client, Sid, <<Acc/binary, D/binary>>);
        {h2, Client, {closed, R}} -> ct:fail({closed_before_body, R});
        {h2, Client, _} -> client_body(Client, Sid, Acc)
    after 5000 -> ct:fail({no_body, Acc})
    end.

url(Scheme, Config, Path) ->
    Host = case Scheme of https -> "localhost"; http -> "127.0.0.1" end,
    lists:flatten(io_lib:format("~s://~s:~p~s",
                                [Scheme, Host, ?config(port, Config), Path])).

start_curl(Config, Args) ->
    Exe = ?config(curl, Config),
    ct:pal("curl ~s", [lists:join(" ", Args)]),
    erlang:open_port({spawn_executable, Exe},
                     [{args, ["-sS", "--max-time", "20" | Args]},
                      binary, exit_status, use_stdio, stderr_to_stdout]).

wait_curl(Port) ->
    wait_curl(Port, <<>>).

wait_curl(Port, Acc) ->
    receive
        {Port, {data, D}} -> wait_curl(Port, <<Acc/binary, D/binary>>);
        {Port, {exit_status, S}} ->
            ct:pal("curl exit ~p: ~ts", [S, Acc]),
            {S, string:trim(Acc)}
    after 30000 -> ct:fail({curl_timeout, Acc})
    end.

%% curl with HTTP2 in its feature list, or false.
find_curl() ->
    case os:find_executable("curl") of
        false -> false;
        Exe ->
            case string:find(os:cmd(Exe ++ " -V"), "HTTP2") of
                nomatch -> false;
                _ -> Exe
            end
    end.

generate_test_certs(Dir) ->
    CertFile = filename:join(Dir, "server.pem"),
    KeyFile  = filename:join(Dir, "server-key.pem"),
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile]),
    _ = os:cmd(lists:flatten(Cmd)),
    {CertFile, KeyFile}.

flush() ->
    receive _ -> flush() after 0 -> ok end.
