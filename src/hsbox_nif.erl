-module(hsbox_nif).

-export([inc/1]).
-export([xsalsa20_init/3, xsalsa20_derive/2,
	 xsalsa20_generate/2, xsalsa20_combine/2]).
-on_load(init/0).

-define(APPNAME, ?MODULE).
-define(LIBNAME, ?APPNAME).

inc(_) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec xsalsa20_init(Rounds :: pos_integer(), Key :: binary(), Nonce :: binary()) ->
	  {ok, Ctx :: _} | {error, _}.
xsalsa20_init(_Rounds, _Key, _Nonce) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec xsalsa20_derive(Ctx :: _, Nonce :: binary()) -> ok | {error, _}.
xsalsa20_derive(_Ctx, _Nonce) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec xsalsa20_generate(Ctx :: _, Bytes :: pos_integer()) -> Dst :: binary().
xsalsa20_generate(_Ctx, _Bytes) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec xsalsa20_combine(Ctx :: _, Src :: binary()) -> Dst :: binary().
xsalsa20_combine(_Ctx, _Src) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).


init() ->
    SoName =
	case code:priv_dir(?APPNAME) of
	    {error, bad_name} ->
		case filelib:is_dir(filename:join(["..", priv])) of
		    true -> filename:join(["..", priv, ?LIBNAME]);
		    _ -> filename:join([priv, ?LIBNAME])
		end;
	    Dir -> filename:join(Dir, ?LIBNAME)
	end,
    ok = erlang:load_nif(SoName, 0).
