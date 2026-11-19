%% @doc HTTP/2 header list validation and reading (RFC 9113 §8, RFC 8441).
%%
%% Everything here is a pure function of a decoded header list: is this a
%% well-formed request, response or trailer section, and what does it say
%% (status, content length, method and path). The module knows nothing about
%% connections, streams or sockets. `h2_connection' decides what to do with a
%% verdict: which stream it concerns and whether to reset it.
%%
%% Internal: use the `h2' module. To add or change a header rule, start here
%% and cite the RFC section next to the check.
-module(h2_headers).

%% Validation of a received header block.
-export([validate_initial_headers/2, validate_trailers/2]).
%% Validation of a header block about to be sent.
-export([validate_outbound_request/1, validate_outbound_response/1,
         has_banned_tunnel_header/1, outbound_response_headers/2]).
%% Reading a header list.
-export([parse_status/1, parse_content_length/1, extract_request_headers/1,
         header_list_size/1, strip_pseudo/1]).
%% Message framing rules that follow from the headers.
-export([no_content_status/2, end_stream_body_mismatch/2]).

-type headers() :: [{binary(), binary()}].

-spec validate_initial_headers(client | server, headers()) ->
    ok | {error, atom()}.
-spec validate_trailers(headers(), EndStream :: boolean()) ->
    ok | {error, atom()}.
-spec validate_outbound_request(headers()) -> ok | {error, atom()}.
-spec validate_outbound_response(headers()) -> ok | {error, atom()}.
-spec has_banned_tunnel_header(headers()) -> boolean().
-spec outbound_response_headers(non_neg_integer(), headers()) -> headers().
-spec parse_status(headers()) -> {ok, 100..599} | malformed.
-spec parse_content_length(headers()) ->
    {ok, non_neg_integer() | undefined} | {error, protocol_error}.
-spec extract_request_headers(headers()) -> {binary(), binary(), headers()}.
-spec header_list_size(headers()) -> non_neg_integer().
-spec strip_pseudo(headers()) -> headers().
-spec no_content_status(binary() | undefined, integer()) -> boolean().
-spec end_stream_body_mismatch(non_neg_integer() | undefined, boolean()) ->
    boolean().

end_stream_body_mismatch(undefined, _EndStream) -> false;
end_stream_body_mismatch(CL, true) when CL > 0  -> true;
end_stream_body_mismatch(_, _)                  -> false.

strip_pseudo(Headers) ->
    lists:filter(fun({N, _}) -> not is_pseudo_header(N) end, Headers).

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
    %% (RFC 8441), `:authority` and `:scheme`. Adapters need these to
    %% reconstruct the request authority/scheme for virtual hosting and
    %% reverse-proxy use; a compliant client may send `:authority` without a
    %% `host` header, so it is not always recoverable otherwise. Consumers
    %% that forward or reflect the header list MUST strip these pseudo-headers
    %% first. `:method` and `:path` are already exposed as separate fields.
    OtherHeaders = lists:filter(
        fun({<<":protocol">>, _}) -> true;
           ({<<":authority">>, _}) -> true;
           ({<<":scheme">>, _})    -> true;
           ({Name, _})             -> not is_pseudo_header(Name)
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

%% RFC 9110 §6.4.1: a final response to HEAD, and any 204 or 304, has no
%% content. A 1xx is interim and never ends the stream (§15.2).
no_content_status(ReqMethod, Status) ->
    Status >= 200 andalso
        (ReqMethod =:= <<"HEAD">> orelse Status =:= 204 orelse Status =:= 304).

%% RFC 9110 §8.6: a server MUST NOT send Content-Length in a 1xx or 204
%% response. Drop it if the caller set one; 304 and HEAD keep theirs.
outbound_response_headers(Status, Headers) when Status < 200; Status =:= 204 ->
    [H || {Name, _} = H <- Headers, Name =/= <<"content-length">>];
outbound_response_headers(_Status, Headers) ->
    Headers.

%% RFC 7540 §8.3: forbidden on a 2xx CONNECT response.
has_banned_tunnel_header(Headers) ->
    lists:any(fun({Name, _}) ->
        Name =:= <<"content-length">> orelse Name =:= <<"transfer-encoding">>
    end, Headers).

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

extract_request_headers_test_() ->
    Req = [{<<":method">>, <<"GET">>},
           {<<":scheme">>, <<"https">>},
           {<<":authority">>, <<"example.com:443">>},
           {<<":path">>, <<"/index">>},
           {<<":protocol">>, <<"websocket">>},
           {<<"accept">>, <<"text/html">>}],
    {Method, Path, Other} = extract_request_headers(Req),
    [%% :method and :path become separate fields.
     ?_assertEqual(<<"GET">>, Method),
     ?_assertEqual(<<"/index">>, Path),
     %% :authority/:scheme/:protocol survive for adapters.
     ?_assertEqual(<<"example.com:443">>, proplists:get_value(<<":authority">>, Other)),
     ?_assertEqual(<<"https">>, proplists:get_value(<<":scheme">>, Other)),
     ?_assertEqual(<<"websocket">>, proplists:get_value(<<":protocol">>, Other)),
     %% :method/:path are stripped from the header list.
     ?_assertEqual(undefined, proplists:get_value(<<":method">>, Other)),
     ?_assertEqual(undefined, proplists:get_value(<<":path">>, Other)),
     %% Regular headers pass through.
     ?_assertEqual(<<"text/html">>, proplists:get_value(<<"accept">>, Other)),
     %% Defaults when :method/:path absent.
     ?_assertEqual({<<"GET">>, <<"/">>, []}, extract_request_headers([]))].

-endif.
