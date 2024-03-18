-module(hsbox_nif).

-export([inc/1]).
-on_load(init/0).

-define(APPNAME, ?MODULE).
-define(LIBNAME, ?APPNAME).

inc(_) ->
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
