-module(hsbox).

-export([xsalsa20_init/3, xsalsa20_derive/2, xsalsa20_combine/2, xsalsa20_generate/2]).

-export([poly1305_init/1, poly1305_update/2, poly1305_finalize/1]).

-export([cb_encrypt/3, cb_decrypt/3]).

-type salsa20_ctx() :: hsbox_nif:salsa20_ctx().
-type poly1305_ctx() :: hsbox_nif:poly1305_ctx().
-type key() :: <<_:256>>.
-type nonce() :: <<_:192>>.

-export_type([salsa20_ctx/0, poly1305_ctx/0, key/0, nonce/0]).


-spec xsalsa20_init(8 | 12 | 20, key(), nonce()) -> salsa20_ctx().
xsalsa20_init(Rounds, Key, Nonce)
  when is_binary(Key), byte_size(Key) == 32,
       is_binary(Nonce), byte_size(Nonce) == 24,
       ((Rounds == 8) or (Rounds == 12) or (Rounds == 20)) ->
    hsbox_nif:xsalsa20_init(Rounds, Key, Nonce).


-spec xsalsa20_derive(salsa20_ctx(), nonce()) -> ok.
xsalsa20_derive(Ctx, Nonce)
  when is_reference(Ctx), is_binary(Nonce), byte_size(Nonce) == 16 ->
    hsbox_nif:xsalsa20_derive(Ctx, Nonce).


-spec xsalsa20_combine(salsa20_ctx(), Src :: binary()) -> Dst :: binary().
xsalsa20_combine(Ctx, Src) when is_reference(Ctx), is_binary(Src) ->
    hsbox_nif:xsalsa20_combine(Ctx, Src).


-spec xsalsa20_generate(salsa20_ctx(), Bytes :: pos_integer()) -> binary().
xsalsa20_generate(Ctx, Bytes)
  when is_reference(Ctx), is_integer(Bytes), Bytes > 0 ->
    hsbox_nif:xsalsa20_generate(Ctx, Bytes).


-spec poly1305_init(key()) -> poly1305_ctx().
poly1305_init(Key) when is_binary(Key), byte_size(Key) == 32 ->
    hsbox_nif:poly1305_init(Key).


-spec poly1305_update(poly1305_ctx(), Data :: binary()) -> ok.
poly1305_update(Ctx, Data) when is_reference(Ctx), is_binary(Data) ->
    hsbox_nif:poly1305_update(Ctx, Data).


-spec poly1305_finalize(poly1305_ctx()) -> MAC :: <<_:128>>.
poly1305_finalize(Ctx) when is_reference(Ctx) ->
    hsbox_nif:poly1305_finalize(Ctx).


-spec cb_decrypt(key(), nonce(), CT :: binary()) ->
	  {ok, PT :: binary()} | {error, _}.
cb_decrypt(Secret, Nonce, <<Tag:16/binary, CT/binary>>) ->
    {Rs, PT} = xsalsa20(Secret, Nonce, CT),
    case poly1305_auth(Rs, CT) of
	Tag -> {ok, PT};
	_ -> {error, auth_fail}
    end.


-spec cb_encrypt(key(), nonce(), PT :: binary()) -> CT :: binary().
cb_encrypt(Secret, Nonce, PT) ->
    {Rs, CT} = xsalsa20(Secret, Nonce, PT),
    Tag = poly1305_auth(Rs, CT),
    <<Tag/binary, CT/binary>>.


xsalsa20(Secret, <<Iv0:8/binary, Iv1/binary>>, Msg) ->
    Ctx = xsalsa20_init(20, Secret, <<0:128, Iv0/binary>>),
    ok = xsalsa20_derive(Ctx, Iv1),
    Rs = xsalsa20_generate(Ctx, 32),
    {Rs, xsalsa20_combine(Ctx, Msg)}.


poly1305_auth(Key, Data) ->
    Ctx = poly1305_init(Key),
    ok = poly1305_update(Ctx, Data),
    poly1305_finalize(Ctx).
