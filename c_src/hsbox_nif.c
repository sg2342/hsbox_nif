#include "erl_nif.h"
#include "crypton_xsalsa.h"


static ErlNifResourceType *salsa_ctx;

static ERL_NIF_TERM inc_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int y, ret;
  if (!enif_get_int(env, argv[0], &y)) {
    return enif_make_badarg(env);
  }
  ret = y + 1;
  return enif_make_int(env, ret);
}

static ERL_NIF_TERM xsalsa20_init_nif(ErlNifEnv* env, int argc,
				      const ERL_NIF_TERM argv[])
{
  void *ctx = enif_alloc_resource(salsa_ctx, sizeof(crypton_salsa_context));
  ERL_NIF_TERM ret = enif_make_resource(env, ctx);

  uint32_t nb_rounds;
  ErlNifBinary key, nonce;

  if (!enif_get_uint(env, argv[0], &nb_rounds) ||
      !enif_inspect_binary(env, argv[1], &key) ||
      !enif_inspect_binary(env, argv[2], &nonce))
    return enif_make_badarg(env);

  crypton_xsalsa_init((crypton_salsa_context*) ctx, nb_rounds,
		      key.size, key.data, nonce.size, nonce.data);

  return enif_make_tuple2(env, enif_make_atom(env, "ok"), ret);  
}

static ERL_NIF_TERM xsalsa20_derive_nif(ErlNifEnv* env, int argc,
					const ERL_NIF_TERM argv[])
{
  void *ctx;
  ErlNifBinary nonce;

  if (!enif_get_resource(env, argv[0], salsa_ctx, &ctx) ||
      !enif_inspect_binary(env, argv[1], &nonce))
    return enif_make_badarg(env);

  crypton_xsalsa_derive((crypton_salsa_context *) ctx, nonce.size, nonce.data);
  return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM xsalsa20_combine_nif(ErlNifEnv* env, int argc,
					 const ERL_NIF_TERM argv[])
{
  void *ctx;
  ErlNifBinary src;

  if (!enif_get_resource(env, argv[0], salsa_ctx, &ctx) ||
      !enif_inspect_binary(env, argv[1], &src))
    return enif_make_badarg(env);

  ERL_NIF_TERM ret;
  uint8_t* dst = enif_make_new_binary(env, src.size, &ret);

  crypton_salsa_combine(dst, (crypton_salsa_context*) ctx, src.data, src.size);

  return ret;
}

static ERL_NIF_TERM xsalsa20_generate_nif(ErlNifEnv* env, int argc,
					  const ERL_NIF_TERM argv[])
{
  void *ctx;
  uint32_t bytes;

  if (!enif_get_resource(env, argv[0], salsa_ctx, &ctx) ||
      !enif_get_uint(env, argv[1], &bytes))
    return enif_make_badarg(env);

  ERL_NIF_TERM ret;
  uint8_t* dst = enif_make_new_binary(env, bytes, &ret);

  crypton_salsa_generate(dst, (crypton_salsa_context*) ctx, bytes);

  return ret;
}

static void salsa_ctx_dtor(ErlNifEnv* env, crypton_salsa_context *ctx) {
}

int on_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info)
{
  ErlNifResourceFlags tried;
  salsa_ctx = enif_open_resource_type(env, "hsbox_nif", "xsalsa20",
				      (ErlNifResourceDtor*) salsa_ctx_dtor,
				      ERL_NIF_RT_CREATE, &tried);
  return 0;
  
}

static ErlNifFunc nif_funcs[] = {
  {"xsalsa20_init", 3, xsalsa20_init_nif},
  {"xsalsa20_derive", 2, xsalsa20_derive_nif},
  {"xsalsa20_generate", 2, xsalsa20_generate_nif},
  {"xsalsa20_combine", 2, xsalsa20_combine_nif},
  {"inc", 1, inc_nif}
};

ERL_NIF_INIT(hsbox_nif, nif_funcs, &on_load, NULL, NULL, NULL)
