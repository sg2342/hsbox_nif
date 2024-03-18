-module(hsbox_nif).

-export([xsalsa20_init/3, xsalsa20_derive/2,
	 xsalsa20_generate/2, xsalsa20_combine/2]).

-export([poly1305_init/1, poly1305_update/2, poly1305_finalize/1]).

-on_load(init/0).

-define(APPNAME, ?MODULE).
-define(LIBNAME, ?APPNAME).

-type salsa20_ctx() :: reference().
-type poly1305_ctx() :: reference().
-export_type([salsa20_ctx/0, poly1305_ctx/0]).

-spec xsalsa20_init(8|12|20, Key :: binary(), Nonce :: binary()) ->
	  salsa20_ctx().
xsalsa20_init(_Rounds, _Key, _Nonce) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec xsalsa20_derive(salsa20_ctx(), Nonce :: binary()) -> ok.
xsalsa20_derive(_Ctx, _Nonce) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec xsalsa20_generate(salsa20_ctx(), NBytes :: pos_integer()) -> Dst :: binary().
xsalsa20_generate(_Ctx, _Bytes) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec xsalsa20_combine(salsa20_ctx(), PT :: binary()) -> CT :: binary().
xsalsa20_combine(_Ctx, _PT) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec poly1305_init(Key :: binary()) -> poly1305_ctx().
poly1305_init(_Key) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec poly1305_update(poly1305_ctx(), Data :: binary()) -> ok.
poly1305_update(_Ctx, _Data) ->
    erlang:nif_error({nif_not_loaded, module, ?MODULE, line, ?LINE}).

-spec poly1305_finalize(poly1305_ctx()) -> Mac :: binary().
poly1305_finalize(_Ctx) ->
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
