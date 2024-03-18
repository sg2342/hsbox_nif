-module(hsbox).

-export([xsalsa20_init/3, xsalsa20_derive/2, xsalsa20_combine/2, xsalsa20_generate/2]).

-export([poly1305_init/1, poly1305_update/2, poly1305_finalize/1]).

xsalsa20_init(Rounds, Key, Nonce)
  when is_binary(Key), byte_size(Key) == 32,
       is_binary(Nonce), byte_size(Nonce) == 24,
       ((Rounds == 8) or (Rounds == 12) or (Rounds == 20)) ->
    hsbox_nif:xsalsa20_init(Rounds, Key, Nonce).

xsalsa20_derive(Ctx, Nonce)
  when is_reference(Ctx), is_binary(Nonce), byte_size(Nonce) == 16 ->
    hsbox_nif:xsalsa20_derive(Ctx, Nonce).

xsalsa20_combine(Ctx, Src) when is_reference(Ctx), is_binary(Src) ->
    hsbox_nif:xsalsa20_combine(Ctx, Src).

xsalsa20_generate(Ctx, Bytes)
  when is_reference(Ctx), is_integer(Bytes), Bytes > 0 ->
    hsbox_nif:xsalsa20_generate(Ctx, Bytes).

poly1305_init(Key) when is_binary(Key), byte_size(Key) == 32 ->
    hsbox_nif:poly1305_init(Key).

poly1305_update(Ctx, Data) when is_reference(Ctx), is_binary(Data) ->
    hsbox_nif:poly1305_update(Ctx, Data).

poly1305_finalize(Ctx) when is_reference(Ctx) ->
    hsbox_nif:poly1305_finalize(Ctx).
