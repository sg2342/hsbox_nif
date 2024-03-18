-module(hsbox_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([init_per_suite/1, end_per_suite/1,
	 init_per_testcase/2, end_per_testcase/2,
	 all/0, suite/0,
	 xsalsa20_kat/1, poly1305_kat/1, sb/1]).


suite() -> [{timetrap,{seconds,30}}].


init_per_suite(Config) -> Config.


end_per_suite(_Config) -> ok.


init_per_testcase(_TestCase, Config) -> Config.


end_per_testcase(_TestCase, _Config) -> ok.


all() -> [xsalsa20_kat, poly1305_kat, sb].


xsalsa20_kat(_Config) ->
    Rounds = 20,
    K = <<"4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742">>,
    N = <<"69696EE955B62B73CD62BDA875FC73D68219E0036B7A0B37">>,
    PT = <<"BE075FC53C81F2D5CF141316EBEB0C7B5228C52A4C62CBD44B66849B64244FFCE"
           "5ECBAAF33BD751A1AC728D45E6C61296CDC3C01233561F41DB66CCE314ADB310E"
	   "3BE8250C46F06DCEEA3A7FA1348057E2F6556AD6B1318A024A838F21AF1FDE048"
	   "977EB48F59FFD4924CA1C60902E52F0A089BC76897040E082F937763848645E07"
	   "05">>,
    CT = <<"8E993B9F48681273C29650BA32FC76CE48332EA7164D96A4476FB8C531A1186AC"
	   "0DFC17C98DCE87B4DA7F011EC48C97271D2C20F9B928FE2270D6FB863D51738B4"
	   "8EEEE314A7CC8AB932164548E526AE90224368517ACFEABD6BB3732BC0E9DA998"
	   "32B61CA01B6DE56244A9E88D5F9B37973F622A43D14A6599B1F654CB45A74E355"
	   "A5">>,

    <<Iv0:8/binary, Iv1/binary>> = binary:decode_hex(N),
    Ctx = hsbox:xsalsa20_init(Rounds, binary:decode_hex(K),
			      <<0:128, Iv0/binary>>),
    ok = hsbox:xsalsa20_derive(Ctx, Iv1),
    _ = hsbox:xsalsa20_generate(Ctx, 32),
    true = (binary:decode_hex(CT) ==
		hsbox:xsalsa20_combine(Ctx, binary:decode_hex(PT))),
    ok.


poly1305_kat(_Config) ->
    Key = <<"85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b">>,
    Msg = <<"Cryptographic Forum Research Group">>,
    Tag = <<"a8061dc1305136c6c22b8baf0c0127a9">>,

    Ctx = hsbox:poly1305_init(binary:decode_hex(Key)),
    ok = hsbox:poly1305_update(Ctx, Msg),
    true = (binary:decode_hex(Tag) == hsbox:poly1305_finalize(Ctx)),
    ok.


sb(_Config) ->
    Key = crypto:strong_rand_bytes(32),
    Nonce = crypto:strong_rand_bytes(24),
    PT = crypto:strong_rand_bytes(1024),

    CT = hsbox:sbEncrypt(Key, Nonce, PT),
    {ok, PT} = hsbox:sbDecrypt(Key, Nonce, CT),
    {error, auth_fail} = hsbox:sbDecrypt(Key, Nonce, <<0, CT/binary>>),
    ok.
