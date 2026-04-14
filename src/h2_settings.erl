%% @doc HTTP/2 Settings (RFC 7540 Section 6.5)
%%
%% Settings are used to communicate configuration parameters between
%% HTTP/2 endpoints. Each setting is identified by a 16-bit identifier
%% and has a 32-bit value.
%%
-module(h2_settings).

-export([default/0, encode/1, decode/1]).
-export([get/2, set/3, merge/2]).
-export([validate/1, validate/2]).

-include("h2.hrl").

%% Settings map type
-type settings() :: #{
    header_table_size => non_neg_integer(),
    enable_push => 0 | 1,
    max_concurrent_streams => non_neg_integer() | unlimited,
    initial_window_size => non_neg_integer(),
    max_frame_size => non_neg_integer(),
    max_header_list_size => non_neg_integer() | unlimited,
    enable_connect_protocol => 0 | 1
}.

-export_type([settings/0]).

%% @doc Return the default settings values.
-spec default() -> settings().
default() ->
    #{
        header_table_size => ?DEFAULT_HEADER_TABLE_SIZE,
        enable_push => ?DEFAULT_ENABLE_PUSH,
        max_concurrent_streams => ?DEFAULT_MAX_CONCURRENT_STREAMS,
        initial_window_size => ?DEFAULT_INITIAL_WINDOW_SIZE,
        max_frame_size => ?DEFAULT_MAX_FRAME_SIZE,
        max_header_list_size => ?DEFAULT_MAX_HEADER_LIST_SIZE,
        enable_connect_protocol => 0
    }.

%% @doc Get a setting value.
-spec get(atom(), settings()) -> term().
get(Key, Settings) ->
    maps:get(Key, Settings, maps:get(Key, default())).

%% @doc Set a setting value.
-spec set(atom(), term(), settings()) -> settings().
set(Key, Value, Settings) ->
    maps:put(Key, Value, Settings).

%% @doc Merge new settings into existing settings.
-spec merge(settings(), settings()) -> settings().
merge(Base, New) ->
    maps:merge(Base, New).

%% @doc Encode settings to binary for SETTINGS frame payload.
-spec encode(settings()) -> binary().
encode(Settings) ->
    encode_settings(maps:to_list(Settings), <<>>).

encode_settings([], Acc) ->
    Acc;
encode_settings([{Key, Value}|Rest], Acc) ->
    case setting_id(Key) of
        undefined ->
            %% Skip unknown settings
            encode_settings(Rest, Acc);
        Id ->
            V = encode_value(Value),
            encode_settings(Rest, <<Acc/binary, Id:16, V:32>>)
    end.

setting_id(header_table_size) -> ?SETTINGS_HEADER_TABLE_SIZE;
setting_id(enable_push) -> ?SETTINGS_ENABLE_PUSH;
setting_id(max_concurrent_streams) -> ?SETTINGS_MAX_CONCURRENT_STREAMS;
setting_id(initial_window_size) -> ?SETTINGS_INITIAL_WINDOW_SIZE;
setting_id(max_frame_size) -> ?SETTINGS_MAX_FRAME_SIZE;
setting_id(max_header_list_size) -> ?SETTINGS_MAX_HEADER_LIST_SIZE;
setting_id(enable_connect_protocol) -> ?SETTINGS_ENABLE_CONNECT_PROTOCOL;
setting_id(_) -> undefined.

encode_value(unlimited) -> 16#ffffffff;
encode_value(V) when is_integer(V) -> V.

%% @doc Decode binary SETTINGS frame payload to settings map.
-spec decode(binary()) -> {ok, settings()} | {error, term()}.
decode(Bin) ->
    decode_settings(Bin, #{}).

decode_settings(<<>>, Acc) ->
    {ok, Acc};
decode_settings(<<Id:16, Value:32, Rest/binary>>, Acc) ->
    case setting_name(Id) of
        {ok, Name} ->
            V = decode_value(Name, Value),
            decode_settings(Rest, maps:put(Name, V, Acc));
        unknown ->
            %% RFC 7540 Section 6.5.2: Unknown settings MUST be ignored
            decode_settings(Rest, Acc)
    end;
decode_settings(Bin, _Acc) when byte_size(Bin) > 0, byte_size(Bin) < 6 ->
    {error, {incomplete_setting, Bin}}.

setting_name(?SETTINGS_HEADER_TABLE_SIZE) -> {ok, header_table_size};
setting_name(?SETTINGS_ENABLE_PUSH) -> {ok, enable_push};
setting_name(?SETTINGS_MAX_CONCURRENT_STREAMS) -> {ok, max_concurrent_streams};
setting_name(?SETTINGS_INITIAL_WINDOW_SIZE) -> {ok, initial_window_size};
setting_name(?SETTINGS_MAX_FRAME_SIZE) -> {ok, max_frame_size};
setting_name(?SETTINGS_MAX_HEADER_LIST_SIZE) -> {ok, max_header_list_size};
setting_name(?SETTINGS_ENABLE_CONNECT_PROTOCOL) -> {ok, enable_connect_protocol};
setting_name(_) -> unknown.

decode_value(max_concurrent_streams, 16#ffffffff) -> unlimited;
decode_value(max_header_list_size, 16#ffffffff) -> unlimited;
decode_value(_, Value) -> Value.

%% @doc Validate settings values (mode-agnostic).
%% Returns ok if valid, or {error, {setting, Reason}} if invalid.
-spec validate(settings()) -> ok | {error, term()}.
validate(Settings) ->
    validate_settings(maps:to_list(Settings), any).

%% @doc Validate settings values from the perspective of `Mode`. The mode
%% matters for RFC 9113 §6.5.2 — a client that receives
%% SETTINGS_ENABLE_PUSH with any value other than 0 MUST treat this as a
%% connection PROTOCOL_ERROR. Servers enforce only the 0|1 range.
-spec validate(settings(), client | server | any) -> ok | {error, term()}.
validate(Settings, Mode) ->
    validate_settings(maps:to_list(Settings), Mode).

validate_settings([], _Mode) ->
    ok;
%% RFC 9113 §6.5.2: clients MUST reject enable_push != 0.
validate_settings([{enable_push, 0}|Rest], Mode) ->
    validate_settings(Rest, Mode);
validate_settings([{enable_push, 1}|_], client) ->
    {error, {enable_push, {forbidden_for_client, 1}}};
validate_settings([{enable_push, 1}|Rest], Mode) ->
    validate_settings(Rest, Mode);
validate_settings([{enable_push, V}|_], _Mode) ->
    {error, {enable_push, {invalid_value, V}}};
validate_settings([{enable_connect_protocol, V}|Rest], Mode) when V == 0; V == 1 ->
    validate_settings(Rest, Mode);
validate_settings([{enable_connect_protocol, V}|_], _Mode) ->
    {error, {enable_connect_protocol, {invalid_value, V}}};
validate_settings([{initial_window_size, V}|_], _Mode) when V > ?MAX_WINDOW_SIZE ->
    {error, {initial_window_size, {exceeds_max, V}}};
validate_settings([{initial_window_size, V}|Rest], Mode) when is_integer(V), V >= 0 ->
    validate_settings(Rest, Mode);
validate_settings([{max_frame_size, V}|_], _Mode) when V < ?MIN_FRAME_SIZE ->
    {error, {max_frame_size, {below_min, V}}};
validate_settings([{max_frame_size, V}|_], _Mode) when V > ?MAX_FRAME_SIZE ->
    {error, {max_frame_size, {exceeds_max, V}}};
validate_settings([{max_frame_size, V}|Rest], Mode) when is_integer(V) ->
    validate_settings(Rest, Mode);
validate_settings([{header_table_size, V}|Rest], Mode) when is_integer(V), V >= 0 ->
    validate_settings(Rest, Mode);
validate_settings([{max_concurrent_streams, unlimited}|Rest], Mode) ->
    validate_settings(Rest, Mode);
validate_settings([{max_concurrent_streams, V}|Rest], Mode) when is_integer(V), V >= 0 ->
    validate_settings(Rest, Mode);
validate_settings([{max_header_list_size, unlimited}|Rest], Mode) ->
    validate_settings(Rest, Mode);
validate_settings([{max_header_list_size, V}|Rest], Mode) when is_integer(V), V >= 0 ->
    validate_settings(Rest, Mode);
validate_settings([{_, _}|Rest], Mode) ->
    %% Unknown settings are ignored
    validate_settings(Rest, Mode).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

default_test() ->
    D = default(),
    ?assertEqual(4096, maps:get(header_table_size, D)),
    ?assertEqual(1, maps:get(enable_push, D)),
    ?assertEqual(unlimited, maps:get(max_concurrent_streams, D)),
    ?assertEqual(65535, maps:get(initial_window_size, D)),
    ?assertEqual(16384, maps:get(max_frame_size, D)),
    ?assertEqual(unlimited, maps:get(max_header_list_size, D)),
    ?assertEqual(0, maps:get(enable_connect_protocol, D)).

encode_decode_test() ->
    Settings = #{
        header_table_size => 8192,
        enable_push => 0,
        max_concurrent_streams => 100,
        initial_window_size => 32768,
        enable_connect_protocol => 1
    },
    Encoded = encode(Settings),
    {ok, Decoded} = decode(Encoded),
    ?assertEqual(8192, maps:get(header_table_size, Decoded)),
    ?assertEqual(0, maps:get(enable_push, Decoded)),
    ?assertEqual(100, maps:get(max_concurrent_streams, Decoded)),
    ?assertEqual(32768, maps:get(initial_window_size, Decoded)),
    ?assertEqual(1, maps:get(enable_connect_protocol, Decoded)).

decode_unknown_setting_test() ->
    %% Unknown settings (id=0xff) should be ignored
    Bin = <<16#ff:16, 42:32, ?SETTINGS_ENABLE_PUSH:16, 0:32>>,
    {ok, Decoded} = decode(Bin),
    ?assertEqual(0, maps:get(enable_push, Decoded)),
    ?assertEqual(false, maps:is_key(unknown, Decoded)).

validate_test_() ->
    [
        ?_assertEqual(ok, validate(default())),
        ?_assertEqual(ok, validate(#{enable_push => 0})),
        ?_assertEqual(ok, validate(#{enable_connect_protocol => 1})),
        ?_assertEqual(ok, validate(#{max_frame_size => 16384})),
        ?_assertEqual(ok, validate(#{max_frame_size => ?MAX_FRAME_SIZE})),
        ?_assertMatch({error, {enable_push, _}}, validate(#{enable_push => 2})),
        ?_assertMatch({error, {max_frame_size, _}}, validate(#{max_frame_size => 100})),
        ?_assertMatch({error, {max_frame_size, _}}, validate(#{max_frame_size => 17000000})),
        ?_assertMatch({error, {initial_window_size, _}}, validate(#{initial_window_size => 16#80000000}))
    ].

merge_test() ->
    Base = #{header_table_size => 4096, enable_push => 1},
    New = #{enable_push => 0, max_concurrent_streams => 50},
    Merged = merge(Base, New),
    ?assertEqual(4096, maps:get(header_table_size, Merged)),
    ?assertEqual(0, maps:get(enable_push, Merged)),
    ?assertEqual(50, maps:get(max_concurrent_streams, Merged)).

-endif.
