#include "erl_nif.h"

static ERL_NIF_TERM inc_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int y, ret;
  if (!enif_get_int(env, argv[0], &y)) {
    return enif_make_badarg(env);
  }
  ret = y + 1;
  return enif_make_int(env, ret);
}

static ErlNifFunc nif_funcs[] = {
  {"inc", 1, inc_nif}
};

ERL_NIF_INIT(hsbox_nif, nif_funcs, NULL, NULL, NULL, NULL)
