-module(hsbox).

-export([xsalsa20_init/3, xsalsa20_derive/2, xsalsa20_combine/2, xsalsa20_generate/2]).

-export([poly1305_init/1, poly1305_update/2, poly1305_finalize/1]).

-export([sbEncrypt/3, sbDecrypt/3]).

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


sbDecrypt(Secret, Nonce, <<Tag:16/binary, CT/binary>>) ->
    {Rs, PT} = xsalsa20(Secret, Nonce, CT),
    case poly1305_auth(Rs, CT) of
	Tag -> {ok, PT};
	_ -> {error, auth_fail}
    end.


sbEncrypt(Secret, Nonce, PT) ->
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
