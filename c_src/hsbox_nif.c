#include "erl_nif.h"
#include "crypton_xsalsa.h"
#include "crypton_poly1305.h"


static ErlNifResourceType *r_salsa_ctx;
static ErlNifResourceType *r_poly1305_ctx;

static ERL_NIF_TERM xsalsa20_init_nif(ErlNifEnv* env, int argc,
				      const ERL_NIF_TERM argv[])
{
  uint32_t nb_rounds;
  ErlNifBinary key, nonce;

  if (!enif_get_uint(env, argv[0], &nb_rounds) ||
      !enif_inspect_binary(env, argv[1], &key) ||
      !enif_inspect_binary(env, argv[2], &nonce))
    return enif_make_badarg(env);

  void *ctx = enif_alloc_resource(r_salsa_ctx, sizeof(crypton_salsa_context));
  ERL_NIF_TERM ret = enif_make_resource(env, ctx);

  crypton_xsalsa_init((crypton_salsa_context*) ctx, nb_rounds,
		      key.size, key.data, nonce.size, nonce.data);

  return ret;
}

static ERL_NIF_TERM xsalsa20_derive_nif(ErlNifEnv* env, int argc,
					const ERL_NIF_TERM argv[])
{
  void *ctx;
  ErlNifBinary nonce;

  if (!enif_get_resource(env, argv[0], r_salsa_ctx, &ctx) ||
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

  if (!enif_get_resource(env, argv[0], r_salsa_ctx, &ctx) ||
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

  if (!enif_get_resource(env, argv[0], r_salsa_ctx, &ctx) ||
      !enif_get_uint(env, argv[1], &bytes))
    return enif_make_badarg(env);

  ERL_NIF_TERM ret;
  uint8_t* dst = enif_make_new_binary(env, bytes, &ret);

  crypton_salsa_generate(dst, (crypton_salsa_context*) ctx, bytes);

  return ret;
}

static ERL_NIF_TERM poly1305_init_nif(ErlNifEnv* env, int argc,
				      const ERL_NIF_TERM argv[])
{
  ErlNifBinary key;

  if (!enif_inspect_binary(env, argv[0], &key) || key.size != 32)
      return enif_make_badarg(env);

  void *ctx = enif_alloc_resource(r_poly1305_ctx, sizeof(poly1305_ctx));
  ERL_NIF_TERM ret = enif_make_resource(env, ctx);

  crypton_poly1305_init((poly1305_ctx*) ctx, (poly1305_key*)key.data);

  return ret;
}

static ERL_NIF_TERM poly1305_update_nif(ErlNifEnv* env, int argc,
					const ERL_NIF_TERM argv[])
{
  void *ctx;
  ErlNifBinary input;

  if (!enif_get_resource(env, argv[0], r_poly1305_ctx, &ctx) ||
      !enif_inspect_binary(env, argv[1], &input))
    return enif_make_badarg(env);

  crypton_poly1305_update((poly1305_ctx*) ctx, input.data, input.size);

  return enif_make_atom(env, "ok");
}


static ERL_NIF_TERM poly1305_finalize_nif(ErlNifEnv* env, int argc,
					  const ERL_NIF_TERM argv[])
{
  void *ctx;

  if (!enif_get_resource(env, argv[0], r_poly1305_ctx, &ctx))
    return enif_make_badarg(env);

  ERL_NIF_TERM ret;
  uint8_t* mac = enif_make_new_binary(env, 16, &ret);

  crypton_poly1305_finalize(mac, (poly1305_ctx*) ctx);

  return ret;
}

int on_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM info)
{
  ErlNifResourceFlags tried;
  r_salsa_ctx = enif_open_resource_type(env, "hsbox_nif", "xsalsa20",
					NULL, ERL_NIF_RT_CREATE, &tried);
  r_poly1305_ctx = enif_open_resource_type(env, "hsbox_nif", "poly1305",
					   NULL, ERL_NIF_RT_CREATE, &tried);
  return 0;
}

static ErlNifFunc nif_funcs[] = {
  {"xsalsa20_init", 3, xsalsa20_init_nif},
  {"xsalsa20_derive", 2, xsalsa20_derive_nif},
  {"xsalsa20_generate", 2, xsalsa20_generate_nif},
  {"xsalsa20_combine", 2, xsalsa20_combine_nif},
  {"poly1305_init", 1, poly1305_init_nif},
  {"poly1305_update", 2, poly1305_update_nif},
  {"poly1305_finalize", 1, poly1305_finalize_nif}
};

ERL_NIF_INIT(hsbox_nif, nif_funcs, &on_load, NULL, NULL, NULL)
