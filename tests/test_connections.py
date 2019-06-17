#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of adp-api-client.
# https://github.com/adplabs/adp-connection-python

# Copyright © 2015-2016 ADP, LLC.

# Licensed under the Apache License, Version 2.0 (the “License”);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an “AS IS” BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.  See the License for the specific language
# governing permissions and limitations under the License.

from preggy import expect
from urlparse import urlparse, parse_qs
from adp_connection.lib import *
from tests.base import TestCase


class ClientCredentialsTestCase(TestCase):
    def test_cc_connected_true(self):
        config = dict({})
        config['clientID'] = '88a73992-07f2-4714-ab4b-de782acd9c4d'
        config['clientSecret'] = 'a130adb7-aa51-49ac-9d02-0d4036b63541'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['sslCertString'] = '-----BEGIN CERTIFICATE----- MIIH9DCCBdygAwIBAgIKGEyBWwABAAAkazANBgkqhkiG9w0BAQwFADB3MRMwEQYK CZImiZPyLGQBGRYDY29tMRMwEQYKCZImiZPyLGQBGRYDQURQMRIwEAYKCZImiZPy LGQBGRYCQUQxEjAQBgoJkiaJk/IsZAEZFgJFUzEjMCEGA1UEAxMaQURQIEludGVy bmFsIElzc3VpbmcgQ0EgMDEwHhcNMTgwMjE2MTc0NzIyWhcNMjAwMjE2MTc0NzIy WjCBxjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxETAPBgNVBAcT CFJvc2VsYW5kMScwJQYDVQQKEx5BdXRvbWF0aWMgRGF0YSBQcm9jZXNzaW5nLCBJ bmMxGDAWBgNVBAsTD0lubm92YXRpb24gTGFiczEkMCIGA1UEAxMbTGFicyBBUEkg Q2xpZW50IENlcnRpZmljYXRlMSYwJAYJKoZIhvcNAQkBFhd3aWxsaWFtLm55cXVp c3RAYWRwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOSp0P9L 5lPz2QrNwsP3IUDI8wRCw1Av8jl3z0bF53rLNz14o7zzv0Tp0FCdxmOAN9oE+gsN 041jsjoVizef9JcvWnlEljPrA1mGEsiqeF0UBHPNNlrzofaFY0abVNwAj6lWhDKt 1BexjXPxdZrPsiNH3XCmmwjYi9bS5kN7tMmaZ9W4xh4dMp6ljX9eDM/YSZ17fkgW XNqiHsFB/G2CxSQ5Qu0RwSOtonVl3FFuW0hP/cMROUq1EGQspgO7nSGGPu3mgCUF xGJZoUTUv9OQ+jvu9aoiDxTs9Na45oPw8OhfWbbrGA0iBSNxdV6IMWDg8MUbQOnv Py3YNYJCaqM6g8MCAwEAAaOCAzAwggMsMB0GA1UdDgQWBBQFzk1EYEhaT60rKMur Sy2a928RADAfBgNVHSMEGDAWgBSZu06XF8PNPO3T269+lX4+4FvnfDCCATkGA1Ud HwSCATAwggEsMIIBKKCCASSgggEghoHVbGRhcDovLy9DTj1BRFAlMjBJbnRlcm5h bCUyMElzc3VpbmclMjBDQSUyMDAxKDEpLENOPURDMVBSUEtJU1VCQ0ExLENOPUNE UCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25m aWd1cmF0aW9uLERDPUFELERDPUFEUCxEQz1jb20/Y2VydGlmaWNhdGVSZXZvY2F0 aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50hkZo dHRwOi8vcGtpLmVzLmFkLmFkcC5jb20vQ0RQL0FEUCUyMEludGVybmFsJTIwSXNz dWluZyUyMENBJTIwMDEoMSkuY3JsMIIBLAYIKwYBBQUHAQEEggEeMIIBGjCBwwYI KwYBBQUHMAKGgbZsZGFwOi8vL0NOPUFEUCUyMEludGVybmFsJTIwSXNzdWluZyUy MENBJTIwMDEsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QUQsREM9QURQLERDPWNvbT9jQUNl cnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0 eTBSBggrBgEFBQcwAoZGaHR0cDovL3BraS5lcy5hZC5hZHAuY29tL0FJQS9BRFAl MjBJbnRlcm5hbCUyMElzc3VpbmclMjBDQSUyMDAxKDEpLmNydDAOBgNVHQ8BAf8E BAMCBaAwOwYJKwYBBAGCNxUHBC4wLAYkKwYBBAGCNxUIh8uaRoWIo3mJnzPt/z2g qRiBfIenqFWEhfd9AgFkAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBsGCSsGAQQB gjcVCgQOMAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEMBQADggIBAJn4Z4Eb5pp9 tb8aYbrsObkO+AOETrCJJvVGzXMZ0M17/1Ych2CzPRsKuOBM1Mccz6DxqBNZDo+W kcTzsKX4NZ9rxBxb6Zi/Lx7nKvR0TwHdDLhDRABbGqllLxWKBIG1NFx0OnP+PHEv m4LPWR51V75B2ZgyDy784jbo8VcJ33ElcMaLc9WXpmJuub29wQtCe/BtOBr+ju/t qPdafL/IDesoUWVaVqhZ93Pd4KY8A2UP3tLDaQHobd3i4KTjBn+EC9MLu9KssuRi 5znABFxhDcFTAYpFn5S/ADwbYzyg4ha2kAEc566DSBH/ogq56qVfJGY/S0ZlIc5S lIS2scMXjX4r8zBmFw1uYKHOzGD21iN16XLjKd2E5NHTAzkuTqD365lbZCedBvjc 8rhsuvyKcBV3yoIlYLj2w2kMBwGCD+J99pqngR6tCi1KT6x4HNFsZ7KeahXjdIcT JobEcRLVq7GEBg59I5gBkdCcXDbBWDo3uvjEcX/ORo9o6wX1ihnuKSRUTPLx47bP smmh3Iq2eZXLMcrfpxOoa3MFf+tEnbfDhTs3+MizMjnxan+00v5LyK7vHNL1Muso OTp0dQSTV1von5y5DPecmssRb6ybc9hhbOlqwpyumNnC5o+kmMUkkn2Pu2R902qx ZRRZ+8dWub0NVzZrXqjEtVc/TEGBmxzU -----END CERTIFICATE-----'
        config['sslKeystring'] = '-----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA5KnQ/0vmU/PZCs3Cw/chQMjzBELDUC/yOXfPRsXness3PXij vPO/ROnQUJ3GY4A32gT6Cw3TjWOyOhWLN5/0ly9aeUSWM+sDWYYSyKp4XRQEc802 WvOh9oVjRptU3ACPqVaEMq3UF7GNc/F1ms+yI0fdcKabCNiL1tLmQ3u0yZpn1bjG Hh0ynqWNf14Mz9hJnXt+SBZc2qIewUH8bYLFJDlC7RHBI62idWXcUW5bSE/9wxE5 SrUQZCymA7udIYY+7eaAJQXEYlmhRNS/05D6O+71qiIPFOz01rjmg/Dw6F9ZtusY DSIFI3F1XogxYODwxRtA6e8/Ldg1gkJqozqDwwIDAQABAoIBAErvT7tqPygCAH2m 4o3f3fjiIamiy2jq3YFxvu6dindWQ1sUvuv8IRFPYmIY4lvXN/ZtrReUR2DNbCnW x5HKDJjC/u5AyMxo1ucupdc27kzqc28TsB1sPAaSve70loGmeW3wGVCWYKwHFqkJ VxYNvH4NXgc9wg7LEECtSqKQ1rU+EuMb9EkHC16lFj6039MqqeTzwz/3r2k76dZv CqJDPGFwLtEOE256QnOHeXTBrKs6LTmKQAsZ5jTbQb4sjErkI1ZOWGWCdnP+WKZA 8pz0SzhzIgKlEsZKkh3Bgt+pUB6uTFYezU5I0KJqFVw65CZH5AI6bZbWRGrc2UDY smiwRwECgYEA+a8MY+uBY1il6gJutsM/UJ7betlabrhwyru4Gf6GLkMVSB3qWjNi OXBgT/w8O3rSH4E+FK9zTN1fZMS4s3rbo6uUhp0aS3MaWbSqEsGqSyGbAu78WBER LTAyTf2kGhbjmHk2C9qTPoGg6YaisdyRwR7w2Tu6z8HlbbwcLyrm7YECgYEA6nKj wsueRbYoZLutzprXfapwqnR67WtaI/gVKmzRn31IQqWFA4ucwFWKUnvNX6VcGyuZ ykxliwq5S0oRxWLQb92vjFL5W/zu9O2uiJ7da5eyBmzSYQuvh2xQcupyjkZgDZ4f zr0EDhmce8uwC6evxKsJHYlf5DvEAYdbV/Qd20MCgYEA4LAGFmT4Ks67f7pwp0dM 0uAh4ot2Ne0Ek2waYEoLtdXocN1653EWE1ptUY1LJruAG5nSpAq/V4xfK+9bxyfo P4FIR1tZLkyGifNqmTZuaO308M7fhuDU9DVLD6QQ6OlwJuXtHP21Q6qjg4MFJcm3 4HJXiyWVFyEFtZpyQn/5EAECgYBeBtQ+z8MOWlwg6lRuxBMgxzagZk7W4XMpcdmr RjFcMbbFY/TQ0zFuwd/T7OsVLRCfpQDs7W7cMNTXqUEvVM4bz2EUekKf7fU4LgsN qAlNmW1Avmwxl6oyOfKZ5AVFolvrmjtPgucZcJQd4jcctYf87EufmPToaD/YDR1J TRKcWQKBgQCQN7GPScLsLPjB7OL8eyvw+ZQpmtxxX6QrQ73uXCyF4tFa+teSpbkj 9r35IGo9Asa8VK7gLvS7NuACgzPz6vO6KRllRVBbGjmS03u8mRYj/c0RhlRarOg1 DbuyN75TupfTdOCPa8eG1I71FUOsBsMDQ60S2KGAH0MSI0EheXaBBQ== -----END RSA PRIVATE KEY-----'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'client_credentials'

        try:
            cconfig = ConnectionConfiguration()
            cconfig.setGrantType('client_credentials')
            ccConnectionBad = ADPAPIConnectionFactory().createConnection(cconfig)
            ccConnectionBad.connect()
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['initBad']['errCode'])

        ClientCredentialsConfiguration = ConnectionConfiguration().init(config)

        ccConnection = ADPAPIConnectionFactory().createConnection(ClientCredentialsConfiguration)

        ccConnection.connect()

        expect(ClientCredentialsConfiguration.getApiRequestURL()).to_equal('https://iat-api.adp.com')
        expect(ClientCredentialsConfiguration.getDisconnectURL()).to_equal('https://iat-accounts.adp.com/auth/oauth/v2/logout')
        expect(ccConnection.isConnectedIndicator()).to_be_true()

    def test_cc_configErr_missing_clientID(self):
        config = dict({})

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['clientID']['errCode'])

    def test_cc_configErr_missing_clientSecret(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['clientSecret']['errCode'])

    def test_cc_configErr_missing_sslCertPath(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['sslCertPath']['errCode'])

    def test_cc_configErr_missing_sslKeyPath(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['sslKeyPath']['errCode'])

    def test_cc_configErr_missing_tokenServerURL(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['tokenServerURL']['errCode'])

    def test_cc_configErr_missing_disconnectURL(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['disconnectURL']['errCode'])

    def test_cc_configErr_missing_apiRequestURL(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['apiRequestURL']['errCode'])

    def test_cc_configErr_missing_grantType(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['grantType']['errCode'])

    def test_cc_configErr_has_badgrantType(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'badgrantType'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['grantTypeBad']['errCode'])


class AuthorizationTestCase(TestCase):
    def test_ac_connected_returns400(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'authorization_code'
        config['baseAuthorizationURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/authorize'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['redirectURL'] = 'http://localhost:8889/callback'
        config['responseType'] = 'code'
        config['scope'] = 'openid'

        try:
            cconfig = ConnectionConfiguration()
            cconfig.setGrantType('authorization_code')
            ccConnectionBad = ADPAPIConnectionFactory().createConnection(cconfig)
            ccConnectionBad.connect()
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['initBad']['errCode'])

        AuthorizationCodeConfiguration = ConnectionConfiguration().init(config)

        acConnection = ADPAPIConnectionFactory().createConnection(AuthorizationCodeConfiguration)

        authURL = acConnection.getAuthorizationURL()
        state = parse_qs(urlparse(authURL).query)['state'][0]
        acConnection.setSessionState(state)
        authURL = acConnection.getAuthorizationURL()
        acConnection.getConfig().setAuthorizationCode('dummy-auth-code ' + state)
        acConnection.setSessionState('')
        try:
            acConnection.connect()
        except ConnectError as connecterr:
            expect(connecterr.code).to_equal('400')
            expect(acConnection.getExpiration()).to_equal('')
            expect(acConnection.getAccessToken()).to_equal('')
            # set dummy access token to test disconnect
            acConnection.connection['token'] = 'dummy-token'
            acConnection.disconnect()
            expect(acConnection.getAccessToken()).to_equal('')

    def test_ac_configErr_missing_baseAuthorizationURL(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'authorization_code'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['baseAuthorizationURL']['errCode'])

    def test_ac_configErr_missing_redirectURL(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'authorization_code'
        config['baseAuthorizationURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/authorize'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['redirectURL']['errCode'])

    def test_ac_configErr_missing_responseType(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'authorization_code'
        config['baseAuthorizationURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/authorize'
        config['redirectURL'] = 'http://localhost:8889/callback'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['responseType']['errCode'])

    def test_ac_configErr_has_bad_responseType(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'authorization_code'
        config['baseAuthorizationURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/authorize'
        config['redirectURL'] = 'http://localhost:8889/callback'
        config['responseType'] = 'codex1234'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['responseTypeBad']['errCode'])

    def test_ac_configErr_missing_scope(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'authorization_code'
        config['baseAuthorizationURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/authorize'
        config['redirectURL'] = 'http://localhost:8889/callback'
        config['responseType'] = 'code'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['scope']['errCode'])

    def test_ac_configErr_has_bad_scope(self):
        config = dict({})
        config['clientID'] = 'e62f181c-3233-4636-bb82-9be5c9f3e3e0'
        config['clientSecret'] = 'fbce97f8-5d3a-42cc-a774-9126c5270625'
        config['sslCertPath'] = 'tests_certs/cert.pem'
        config['sslKeyPath'] = 'tests_certs/cert.key'
        config['tokenServerURL'] = 'https://iat-api.adp.com/auth/oauth/v2/token'
        config['disconnectURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/logout'
        config['apiRequestURL'] = 'https://iat-api.adp.com'
        config['grantType'] = 'authorization_code'
        config['baseAuthorizationURL'] = 'https://iat-accounts.adp.com/auth/oauth/v2/authorize'
        config['redirectURL'] = 'http://localhost:8889/callback'
        config['responseType'] = 'code'
        config['scope'] = 'openid121212'

        try:
            ConnectionConfiguration().init(config)
        except ConfigError as conferr:
            expect(conferr.code).to_equal(Error.errDict['scopeBad']['errCode'])
