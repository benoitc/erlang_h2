%% @doc HTTP/2 Interop Test Suite
%%
%% Drives our h2 server from h2spec to surface bugs only visible to a
%% third-party peer. Library-level conformance lives in `h2_compliance_SUITE`,
%% which exercises the same code paths with raw `ssl` + `h2_frame` +
%% `h2_hpack`; this suite is strictly for external-peer interop.
%%
%% Install h2spec (macOS): `brew install summerwind/h2spec/h2spec`
%% Install h2spec (Linux): download the release tarball from
%%   https://github.com/summerwind/h2spec/releases.
%%
-module(h2_interop_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, groups/0, suite/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-export([
    h2spec_generic_test/1,
    h2spec_hpack_test/1
]).

%% ============================================================================
%% CT Callbacks
%% ============================================================================

suite() ->
    %% h2spec_generic_test can take ~30 s on a slow runner.
    [{timetrap, {seconds, 120}}].

all() ->
    [{group, h2spec}].

groups() ->
    [{h2spec, [sequence], [h2spec_generic_test, h2spec_hpack_test]}].

init_per_suite(Config) ->
    ok = application:ensure_started(crypto),
    ok = application:ensure_started(asn1),
    ok = application:ensure_started(public_key),
    ok = application:ensure_started(ssl),
    CertDir = ?config(priv_dir, Config),
    {CertFile, KeyFile} = generate_test_certs(CertDir),
    [{cert_file, CertFile}, {key_file, KeyFile} | Config].

end_per_suite(_Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    case tool_for(TestCase) of
        {missing, Tool} ->
            {skip, Tool ++ " not installed"};
        ok ->
            process_flag(trap_exit, true),
            drain_exits(),
            Handler = fun(Conn, StreamId, Method, Path, Headers) ->
                handle_interop_request(Conn, StreamId, Method, Path, Headers)
            end,
            ServerOpts = #{
                cert    => ?config(cert_file, Config),
                key     => ?config(key_file, Config),
                handler => Handler
            },
            case h2:start_server(0, ServerOpts) of
                {ok, ServerRef} ->
                    Port = h2:server_port(ServerRef),
                    [{server_ref, ServerRef}, {port, Port} | Config];
                {error, Reason} ->
                    {skip, {server_start_failed, Reason}}
            end
    end.

tool_for(h2spec_generic_test) -> require("h2spec");
tool_for(h2spec_hpack_test)   -> require("h2spec").

require(Name) ->
    case os:find_executable(Name) of
        false -> {missing, Name};
        _     -> ok
    end.

end_per_testcase(_TestCase, Config) ->
    case ?config(server_ref, Config) of
        undefined -> ok;
        ServerRef -> h2:stop_server(ServerRef)
    end,
    timer:sleep(50),
    drain_exits(),
    ok.

drain_exits() ->
    receive
        {'EXIT', _Pid, _Reason} -> drain_exits()
    after 0 ->
        ok
    end.

%% ============================================================================
%% Server Handler
%% ============================================================================

%% Permissive handler — any method/path returns 200 "ok". h2spec hits
%% arbitrary paths and doesn't care about bodies beyond well-formedness.
handle_interop_request(Conn, StreamId, <<"HEAD">>, _Path, _Headers) ->
    h2:send_response(Conn, StreamId, 200,
        [{<<"content-type">>, <<"text/plain">>}]),
    h2:send_data(Conn, StreamId, <<>>, true);
handle_interop_request(Conn, StreamId, _Method, _Path, _Headers) ->
    h2:send_response(Conn, StreamId, 200,
        [{<<"content-type">>, <<"text/plain">>}]),
    h2:send_data(Conn, StreamId, <<"ok">>, true).

%% ============================================================================
%% h2spec tests
%% ============================================================================

%% First-pass observe mode: no --strict flag; any failures surface in ct:log
%% with the full output so they can be triaged and either fixed or added to a
%% skip list.
h2spec_generic_test(Config) ->
    Port = ?config(port, Config),
    Cmd = io_lib:format(
        "h2spec -h 127.0.0.1 -p ~p -t -k -o 10", [Port]),
    run_h2spec(lists:flatten(Cmd)).

h2spec_hpack_test(Config) ->
    Port = ?config(port, Config),
    Cmd = io_lib:format(
        "h2spec hpack -h 127.0.0.1 -p ~p -t -k -o 10", [Port]),
    run_h2spec(lists:flatten(Cmd)).

run_h2spec(Cmd) ->
    ct:log("~s", [Cmd]),
    Output = os:cmd(Cmd ++ " ; echo __EXIT__=$?"),
    ct:log("~s", [Output]),
    Failed = parse_h2spec_failed(Output),
    Exit   = parse_exit_code(Output),
    case {Failed, Exit} of
        {0, 0} -> ok;
        _ ->
            ct:fail({h2spec_failures, [{failed_cases, Failed}, {exit_code, Exit}]})
    end.

%% h2spec ends its output with "<N> tests, <P> passed, <S> skipped, <F> failed".
%% Output is converted to UTF-8 bytes because `os:cmd` returns codepoints
%% (h2spec uses ✓ / ✗ glyphs).
parse_h2spec_failed(Output) ->
    Bin = unicode:characters_to_binary(Output),
    case re:run(Bin, "(\\d+)\\s+failed", [{capture, [1], binary}]) of
        {match, [N]} -> binary_to_integer(N);
        nomatch      -> -1
    end.

parse_exit_code(Output) ->
    Bin = unicode:characters_to_binary(Output),
    case re:run(Bin, "__EXIT__=(\\d+)", [{capture, [1], binary}]) of
        {match, [N]} -> binary_to_integer(N);
        nomatch      -> -1
    end.

%% ============================================================================
%% Test certs (cloned from h2_compliance_SUITE to keep suites independent).
%% ============================================================================

generate_test_certs(Dir) ->
    CertFile = filename:join(Dir, "server.pem"),
    KeyFile  = filename:join(Dir, "server-key.pem"),
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [KeyFile, CertFile]),
    _ = os:cmd(lists:flatten(Cmd)),
    {CertFile, KeyFile}.
