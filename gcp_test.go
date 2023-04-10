package verysign

import (
	"fmt"
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

func Test_initGCP(t *testing.T) {
	resp := make(map[string]string)
	resp["1"] = "-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----\n"
	resp["2"] = "-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----\n"
	resp["3"] = "-----BEGIN CERTIFICATE-----\nCERT3\n-----END CERTIFICATE-----\n"
	resp["4"] = "-----BEGIN CERTIFICATE-----\nCERT4\n-----END CERTIFICATE-----\n"
	resp["5"] = "-----BEGIN CERTIFICATE-----\nCERT5\n-----END CERTIFICATE-----\n"

	defer gock.Off()
	gock.New("https://www.googleapis.com").
		MatchHeader("Accept", "application/json").
		Get("/oauth2/v1/certs").
		Reply(200).
		JSON(resp)

	vs, err := initGCP()
	assert.NoError(t, err)
	assert.Equal(t, 5, len(vs.certs))
	for k, v := range vs.certs {
		expectedValue := resp[k]
		assert.Equal(t, expectedValue, v)
	}
}

func Test_GCP_VerifySignature(t *testing.T) {
	resp := make(map[string]string)
	resp["1"] = "-----BEGIN CERTIFICATE-----\nAAAAB3NzaC1yc2EAAAADAQABAAACAQDTJ0aK38iQSt47eedDfpbjgFhEKuVawErJbvx33KLi89lCcsH96qZPsB13sIoqkq4987mLGLU0gdj9wLSOdZ6dkkM/OA9PgIWGsSrM7lW5hhVr6EEGHNHGR9HYJ2c8UglcjYxAKPUx/zmzXJgVHVmL35V3moQLH46wgEDGyuW6aS1ZApaCpItn8DayKHTkga2WvbS6HmitcdVtGttp+hBKUjOwB6eE865fupELMSeM6NE4CXrgDyfX3DLfVg9j1P0VE3HO8+++CHxsuAae8NAd+wwdViB3QoXcun3EnHbXTab1d4wKXUTNU2eO0RR/BN2GpQaw9XhpEN3wzzCiRb+vxH2WpJqxuksSqzx5gKawYBqFaE/kFClWQ0duNfm4hJ1xDVxjr8ieAX6RyBfqjblShvO5OtT17UYoUIL+ikmo7gXzAPhlPBFBpVX75Oe3ELXiABEW+NlRd1eW/+ZXvfZTvu1VYEqodUvSTFv9x8iMxo9YrQqTJw72WtTlrZALdg/Uoo855OmJvlSZ7LwNMPXsxHMkdxOAvt+HycPW+u2Lq0cGZOsCo7bZKuehWWUj2hB/a3kvrvskfA6rsaGXV+KBRYZcW7Ef22fBTiISooSHX/sk6FoP4kp3iITKezBmdJKp157WIs8Xxhm6S6LgTFdkpcs7f3u7oN/trwblkI/I3Q==\n-----END CERTIFICATE-----\n"
	resp["2"] = "-----BEGIN CERTIFICATE-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0ydGit/IkEreO3nnQ36W44BYRCrlWsBKyW78d9yi4vPZQnLB/eqmT7Add7CKKpKuPfO5ixi1NIHY/cC0jnWenZJDPzgPT4CFhrEqzO5VuYYVa+hBBhzRxkfR2CdnPFIJXI2MQCj1Mf85s1yYFR1Zi9+Vd5qECx+OsIBAxsrlumktWQKWgqSLZ/A2sih05IGtlr20uh5orXHVbRrbafoQSlIzsAenhPOuX7qRCzEnjOjROAl64A8n19wy31YPY9T9FRNxzvPvvgh8bLgGnvDQHfsMHVYgd0KF3Lp9xJx2102m9XeMCl1EzVNnjtEUfwTdhqUGsPV4aRDd8M8wokW/r8R9lqSasbpLEqs8eYCmsGAahWhP5BQpVkNHbjX5uISdcQ1cY6/IngF+kcgX6o25UobzuTrU9e1GKFCC/opJqO4F8wD4ZTwRQaVV++TntxC14gARFvjZUXdXlv/mV732U77tVWBKqHVL0kxb/cfIjMaPWK0KkycO9lrU5a2QC3YP1KKPOeTpib5Umey8DTD17MRzJHcTgL7fh8nD1vrti6tHBmTrAqO22SrnoVllI9oQf2t5L677JHwOq7Ghl1figUWGXFuxH9tnwU4iEqKEh1/7JOhaD+JKd4iEynswZnSSqdee1iLPF8YZukui4ExXZKXLO397u6Df7a8G5ZCPyN0CAwEAAQ==\n-----END CERTIFICATE-----\n"
	resp["3"] = "-----BEGIN CERTIFICATE-----\nCERT3\n-----END CERTIFICATE-----\n"
	resp["4"] = "-----BEGIN CERTIFICATE-----\nCERT4\n-----END CERTIFICATE-----\n"
	resp["5"] = "-----BEGIN CERTIFICATE-----\nCERT5\n-----END CERTIFICATE-----\n"

	testCases := map[string]struct {
		token string
		err   error
	}{
		"empty token": {
			token: "",
			err:   fmt.Errorf("token contains an invalid number of segments"),
		},
		"aleatory string as token": {
			token: "q3yhah6Jf9dw9FGl2aEsoNVuuJCcVO74Dy7MU5UzN2O2Zui08V1JypTRyQ448vebmiRj0YxLPFIc6qzGIMivU3las5J7fec03EKLS8qKl2t1H0b8kMKG7NH16dfGqGdsV1XyR5VJf6j4CGHdrhTpiP2r0LOWspEfACWpdpMbTXwx9wcOCXGWab0oGvrdQNWmkQYTpSWt",
			err:   fmt.Errorf("token contains an invalid number of segments"),
		},
		"wrong signing method - HS256 token": {
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODA4ODg2NTZ9.LETKXjexZCBJAzUQ8WfI95YPvDbkMZueE-SQPjc-EdM",
			err:   fmt.Errorf("unexpected signing method: HS256"),
		},
		"kid key is not a string": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6NX0.eyJleHAiOjE2ODA4ODg2NTZ9.izGn7-HbNkitltRV896N3gqy6Pwb9fGIp2Yzwby37a8mVlCUaL9f5_0kHAt7UbaaoPu6YQ7U1w-tPr_Cu8gP_KYOTFuc3_vTUHNnXlsFFL9B6SOSlrE9QYumsvP1velk3zz1h_041PVz42dwnxvS04lS5Oo_ttQXmSr48wX4iEBRJwS_Zr_hLsrUFmRN_EwxlpqNI8Iy_Bv5SpWDF7Aa2NP6-xIK_B7e0W1Pb8nZSpaJgcwHQDNoX410jAW3io2eePL410RradlX1B5HYTrbQAP7aNmdW3TT1VW6AzMf_XscGNSkj4NOsVuMTiQ2RUjhfZuYuYoPWyUjbRVlpr-OJKHy-xse9mHDifotqY6YB7EbRuFKQl2DZWYebA8-8b_pUx3ZJCcOm9rYQLqSWutJj4nuH53lMBKLkTfJawfu5Q9kZowXdzarlj9Olng9HNo2nfwvsiqf5fP8nohv8cHKwV8aDpsWWBic9UOYJQD49B2jJyeizuwnWjyZDAW6-1OfXUSe3CyZbg28OsoQIvV6-3eiNNkK3eIy6FSzQUCg63f0JGvCfkDaRYSvAeXyagm41eGFm6XU31qNyR5NkhvAWlXwdlwKfY06Q45oMtYrB-mRQLe55PgSoAJm-iKdkoe7vFXuZRsdFCdtDms2QTW3glnVBXdlYhBY8rHCBw5V598",
			err:   fmt.Errorf("found key ID, but value was not a string"),
		},
		"key not found": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjYifQ.eyJleHAiOjE2ODA4ODg2NTZ9.kNQwyp4Cx3StyR30wzetapLpmK9MrAj_3ZCWJGkYRSt2rl_-ylCb4PiYmjSa6FXW_55hyYFcq_SVt5SYYLkbOVFCxATCzyz1KQqk0huy5Vx2Rbwhkg8hgan5Mf6kjq1fVquan5rwKbcUkharQw435DRhha2B867ht2c35wFryQmUPzqRFnJ810ArM9Os2pyRk7RryBA816GhNMRyTsqKNLsvpRV9gbpN4QdZGCCjwUMmZrRgs62uEroRqtgjZe5WWLy3nM0oWKjsJIinLf4j595OLB1vo4_N8Iyos07yD2W0PPJ9ro73cXOih41lSBV5DnxQ-sGWq-0PBWVrOcX7zmcAByFCCFNf4Gwkxqv5yLlQLGV9udqezFiskosWGlX8wgp4SpAwxcHZaT0-1zZQPyrqvC_TqtvkBbCeQkQM9Fz0t9tOzEEC_nFSytejpBi--Kv7A4QW4VoESaC--i4qF2sccn-NLQlry19nTKF7Z-i1aq_VlLZbwJD6i2rV0XcpdaJuM2VoSyAspBlXnhU7hb6hfX5YMEMPVz7X3cDhD-FS6fvo15OsjCk43vSUu2Qadq48ZRgHQGCExGzVPlmsvFXowbQwAMXS5dm17y0mBqsfb2t4i39MakpLY1pKsmc46Atq3RgdFVOjomxJ_sbQ5zrEXfnaxPylufhJHIAcvZ4",
			err:   fmt.Errorf("no public RSA key found corresponding to key ID from token '6'"),
		},
		"not a pem encoded key": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjUifQ.eyJleHAiOjE2ODA4ODg2NTZ9.Mzh7X1oxtRlG149FwUUIBjIe8Lufglo1MYWsTxvQNuRiABAFXklKwg6C_VnrvXEKnVe2eDmnZR8PDboBoDAVmxQarqTqpiQSHV-ap9f5WBCf7GuyOdJhacUiBq0CZRInMQv1tqNHBq9jCKFcOryFQfGUvmzPXef9km8eKMVPF6GRHxRr8WDWAJw5CzgM3czHcKP3gdqhQSu2ifsEtoVxfLGZqR04l5enpGL1O-cVruVL_qt3UsQF4TCNJs7Mg_1L33DQIKqmuHIU0s_kygSm2blyHbE_IR_Nna3HJggMhOqpzbGyVDXYVlyTZj4jBgafjUYRRHTPEiABAOFJ6sVMYFVVBUFPAD16s_l80-BUS5_GkdV51yWgsBpdiW08eN90Mo1G2V_deS5K2vN3qKakh_e6eKQ3IjX6A9uB_i71L2C_0LUs79vOarRNO9i6mdJknV6zBSKV-XfFpIrV4SQ6vE8q22j3uPGyIe2WoJeYmUWTkmTA7F2GLxrjpOWQBhHFGH0jXDP2pXsNj3w3d1mGNALbnsLBj_LkYKisPpEkEa1oXsAcI9KB-eStHsxZVkrp6qSz-ykeGK29OVbaWICXSFwOcV5Nroh5tkOQ3BD4WA1s5Xp5CfNKCwC9ikxeW68lO98vXJ0O4VHpiaj2ewAEIUH5EXSH_dwHiKKdYDpvb_Y",
			err:   fmt.Errorf("an error occurred parsing the public key base64 for key ID '5'; Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key"),
		},
		"malformed certificate": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJleHAiOjE2ODA4ODg2NTZ9.teSTKOrGttiW3XkBAFEDxb1UhYG1H2ZtFTKd9FLrei2pqq7jjjSd9C0SXHmFIm6luIhdOkmk1lxCwcVqLM-gGOCNeVIepTbNaFyqcVuiDj44ekdQYTP82OnxXakrLQSwRWVI7jtHZGmDlV2STGPA18nXi1brj4I081_hNXUpP9WF1LpMoaVSLyUVgcmraTxuVIqZToSiy1KeG6wwTx--Sin2uSKnykaDnG2OutVi9ccoW0lt7a2ggnKQd_c2sgd7-4bRWRMdxCPPHkTSOegUe7Q5op71HzM_w17YnAF3YEf4RYV22XADUAGYsOH7Hx_HhtSkCI_D_tFxBaFVq4gU13cgsxruCLwF60xIA06AKD_SgJHbBIlVykCwT3ghCQh4Ph_e29BRcyOFOauZiPzbo4RrgFORx_rdzcwelVBOvFhQ2Xf1fPllhZy8B-Kmj4YBJyj-qT9s5sepF67lcBiKVPOegqz4TtPG84h6ELxkzcsiuW5Pc-itsZ62xoD5JbMtN83eqKMuvxn9dkOq5cGOp4qbi0nUCu3Sq5EMk4ju8hJGHI8QEEQp90peEO81rMIlcbVBDjoGHEn5lo08hQbpniZsDgbuhOfMeLQJsgRtyx3iW1CInlpeofXSjn9GtDChZVwM2FRp-mNTUIi08MPQUeNOiwynwRrgz6XUqN3TFVg",
			err:   fmt.Errorf("an error occurred parsing the public key base64 for key ID '1'"),
		},
		"valid token": {
			token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIifQ.eyJleHAiOjk5OTk5OTk5OTl9.nR0m1NBtfLFWdwA1JRcIfOKb4-EzUkqvdYUTy1uYk2GjmNOrndOubWysdVocMe6qPCXgJFTUzgvm9OSPqC7ntEtVzjKXKBAxGHeaQS82wSKD_820WAuOlG6S9PJPvAwGdPix00vAKH_Dx9tB7BK9QVHeBw77dWmu6PC-OTCs1N-Za01OKgzYIbbODbRnirEt4fTMeJexzpW1Ii7J5Yr6QJTw-XhTzMbp5pO3-d_9uMvIkrdzqJRRNqOaffoSftqfRV7pXdrMkbhTCOviv6uEXXkogeVGTgbxlSHz5BKPmjKfd8c4fx_Z0h26cLqbILSJ_2aJLRVKo_Dj_wkEe8M3Dp-4fjZJ2a2pasL6fileZsh2CapyDp0SugC2uEh33NIBbpJb_UlLNrxvdv1fT8hnaNvJspFs-UR-rd7mlhF2ASiIZp_vyJpSrA-mzowYBgcqs_pavbsalloRAhanH9Ozwj8zNyjlrkABs4zma5Ml4iT-p-6Bt8mEODqgGIYynlJHj85UGBML40zBLllRaM3G7sEPBld3gQdSzaGoq4aobNFHtQW3tcLiMqIm9UAtEia_35kA7_j0p4CkyabbsBLFKBc9Qmf63B1M7kLAtI0xEN1ZOes1PSc_rffENigc90AVs9VD81igb8BRhkdzF8U5z8PyhfUGd_iGhXG9z_atokY",
			err:   nil,
		},
	}

	for testName, testCase := range testCases {
		t.Run(testName, func(t *testing.T) {
			// Arrange
			var token *jwt.Token
			defer gock.Off()
			gock.New("https://www.googleapis.com").
				MatchHeader("Accept", "application/json").
				Get("/oauth2/v1/certs").
				Reply(200).
				JSON(resp)

			vs, err := initGCP()
			assert.NoError(t, err)

			// Act
			token, err = vs.VerifySignature(testCase.token)

			// Assert
			if testCase.err != nil {
				assert.Contains(t, err.Error(), testCase.err.Error())
			} else {
				assert.NoError(t, err)
				assert.True(t, token.Valid)
			}
		})
	}
}
