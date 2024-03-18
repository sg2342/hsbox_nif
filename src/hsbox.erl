-module(hsbox).

-export([test/0]).

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

test() ->
    true = xsalsa20_test(),
    true = poly1305_test().

poly1305_test() ->
    Key = binary:decode_hex(<<"85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b">>),
    Msg = <<"Cryptographic Forum Research Group">>,
    Tag = binary:decode_hex(<<"a8061dc1305136c6c22b8baf0c0127a9">>),

    Ctx = poly1305_init(Key),
    ok = poly1305_update(Ctx, Msg),
    Tag == poly1305_finalize(Ctx).

xsalsa20_test() ->
    Rounds = 20,
    Key = binary:decode_hex(<<"4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742">>),
    Nonce = binary:decode_hex(<<"69696EE955B62B73CD62BDA875FC73D68219E0036B7A0B37">>),
    PT = binary:decode_hex(<<"BE075FC53C81F2D5CF141316EBEB0C7B5228C52A4C62CBD44B66849B64244FFCE5ECBAAF33BD751A1AC728D45E6C61296CDC3C01233561F41DB66CCE314ADB310E3BE8250C46F06DCEEA3A7FA1348057E2F6556AD6B1318A024A838F21AF1FDE048977EB48F59FFD4924CA1C60902E52F0A089BC76897040E082F937763848645E0705">>),
    CT = binary:decode_hex(<<"8E993B9F48681273C29650BA32FC76CE48332EA7164D96A4476FB8C531A1186AC0DFC17C98DCE87B4DA7F011EC48C97271D2C20F9B928FE2270D6FB863D51738B48EEEE314A7CC8AB932164548E526AE90224368517ACFEABD6BB3732BC0E9DA99832B61CA01B6DE56244A9E88D5F9B37973F622A43D14A6599B1F654CB45A74E355A5">>),

    <<Iv0:8/binary, Iv1/binary>> = Nonce,
    Ctx = xsalsa20_init(Rounds, Key,
			<<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, Iv0/binary>>),
    ok = xsalsa20_derive(Ctx, Iv1),
    _ = xsalsa20_generate(Ctx, 32),
    CT == xsalsa20_combine(Ctx, PT).
