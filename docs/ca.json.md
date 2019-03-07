# Detailed CA configuration

Note that JSON does not support comments, so this example won't be functional.

```js
{
    // Path to root file, an array of multiple roots is also supported.
    // Mandatory.
    "root": "/home/user/.step/certs/root_ca.crt",
    // Path to federated roots.
    // Optional.
    "federatedRoots": [],
    // Path to the intermediate certificate.
    // Mandatory.
    "crt": "/home/user/.step/certs/intermediate_ca.crt",
    // Path to the intermediate certificate key.
    // Mandatory.
    "key": "/home/user/.step/secrets/intermediate_ca_key",
    // Password to decrypt the intermediate certificate key.
    // Optional.
    "password": "a-password",
    // Address to listen, it can be a ":port" or "ip:port".
    // Mandatory.
    "address": ":9443",
    // List of domain names or IPs for the CA.
    // Mandatory.
    "dnsNames": [
        "ca.smallstep.com"
    ],
    // Logger configuration, it will only log if this field is present.
    // Optional.
    "logger": {
        // Format for the logs ("text" (default), "json", or "common")
        "format": "text",
        // HTTP header to use as the request-id, defaults to "X-Smallstep-Id".
        // If a value is not present a time-based one will be created.
        "traceHeader": "X-Smallstep-Id",
    },
    // Monitoring support, only newrelic.com is supported at this time.
    // Optional.
    "monitoring": {
        // Type of monitoring, defaults to "newrelic".
        "type": "newrelic",
        // New Relic application name.
        "name": "new-relic-app-name",
        // New Relic license key.
        "key": "new-relic-license-key"
    },
    // TLS configuration.
    // Optional, defaults to this configuration.
    "tls": {
        // Supported cipher-suites.
        // Default to the following list.
        "cipherSuites": [
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        ],
        // Minimum TLS version supported.
        "minVersion": 1.2,
        // Maximum TLS version supported.
        "maxVersion": 1.2,
        // TLS renegotation support. If enabled, it allows a remote server to
        // repeatedly request renegotiation.
        "renegotiation": false
    },
    // Authority configuration.
    // Mandatory.
    "authority": {
        // Default claims for all provisioners.
        // Optional.
        "claims": {
            // Minimum duration for a TLS certificate.
            // Optional, defaults to 5m.
            "minTLSCertDuration": "5m",
            // Maximum duration for a TLS certificate.
            // Optional, defaults to 24h.
            "maxTLSCertDuration": "24h",
            // Default duration for a TLS certificate.
            // Optional, defaults to 24h.
            "defaultTLSCertDuration": "24h",
            // Disable renewal of certificates.
            // Optional, defaults to false
            "disableRenewal": false
        },
        // Disable the check for the iat (issued at).
        // If false, only times after the start of the CA will be accepted.
        // Optional, defaults to false.
        "disableIssuedAtCheck": false,
        // Certificate subject template.
        // Optional.
        "template": {
            "country": "US",
            "organization": "Smallstep",
            "organizationalUnit": "The core unit",
            "locality": "San Francisco",
            "province": "CA",
            "streetAddress": "123 First St."
        },
        // List of provisioners.
        // Mandatory, at least one is required.
        "provisioners": [
            {
                // Name of provisioner.
                // Mandatory.
                "name": "dev@smallstep.com",
                // Type of provisioner.
                // Mandatory.
                "type": "jwk",
                // JWK public key.
                // Mandatory.
                "key": {
                    "use": "sig",
                    "kty": "EC",
                    "kid": "303iMuvAIzxjFNTSVy4iT0ZoScjl7yoM_ca7S__kous",
                    "crv": "P-256",
                    "alg": "ES256",
                    "x": "Hw0_-aAqysXbk3O7rFb2x8Y_L2MWkl6IQ10jRCCJW9I",
                    "y": "wlDo1SXqn5K8ebraQVoC9weczleOpHQH3vTv6ZUUqVc"
                },
                // Claims for this provisioner.
                // Optional.
                "claims": {
                    "minTLSCertDuration": "5m",
                    "maxTLSCertDuration": "72h",
                    "defaultTLSCertDuration": "48h",
                    "disableRenewal": false
                },
                // Encrypted private key
                // Optional.
                "encryptedKey": "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEwMDAwMCwicDJzIjoiV0tSVkpLR3ZJbGxpWHhMRDZhOGlqdyJ9.Nm7qs3znYceEKynXp82EibieZBscGuPnrSm9NN069gvnn_9oWodZqQ.shgkK_xGjf8qDYfg.if19bn9neIHd_Ngd6sfDqmEb4t6Nm7IXUeP8BWf24SJvnAmm6Jmuke-Qvy2cNCl_zgF4cxVCbXJ8mShuOV25wa5yRwZxSq7nFYAzExJnwUZ6z78JRnMp-OycohDqbNujhV9K3GjQLqDySCXytzZoKOaP8yWmtTD1BRX8D7W956FOL8oFADOwLHQENhGLklr5w-RCq-AnZC9Mhn6383DVVs__i8TYIw9X80nEQcN_uQY3gd3cU8nOlf_XjWQZNY2yDoN6GVh6dxE362wKxA6dua7hrjkKoaGRdMA9D5ZAWGaxQXa25Zka5rOS6SVo0XuIkVYFX-WY0vVmsO0FUYM.zRSx_Q5GK4gg7m_Fi2BDDg"
            },
            {
                "name": "staging@smallstep.com",
                "type": "jwk",
                "key": {
                    "use": "sig",
                    "kty": "EC",
                    "kid": "gtm9V9wHwiCYnaMQx6PpVsNwdBZJ7zOCud1SHW323tY",
                    "crv": "P-256",
                    "alg": "ES256",
                    "x": "bhn4A2gNH1Y0ubjWUCD_MgNLGzzNNjI55SqqWAFJdjs",
                    "y": "NUA2yIGdn9ucGggV05r54AjBSnzqmCDpTHS1A3c4UNM"
                },
                "claims": {
                    "minTLSCertDuration": "5m",
                    "maxTLSCertDuration": "12h",
                    "defaultTLSCertDuration": "4h",
                    "disableRenewal": false
                },
                "encryptedKey": "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEwMDAwMCwicDJzIjoiUlZQeTV5c3BGQXduSFpLNmdKdU1yUSJ9.98CLZKtTeiAodBMhn1T51IMt2RY6OT0pPXbZ7c6FULINrkon_TV8Ig.cRVuQCvisUlxhnSb.kAmBXBt3Q8VQkhu40IXc-WbyqNBV9dQG0pHNWy158ow-qcqJohJzZqVJDnM3VkmQ8-K5nxox-m9mVRU6rzOcNz129vHimfsQBTzbJfX9A-l7erJfJppQ1-NTS-_3rLNe455g0OWvk7c09RcBlA-IJ_NgMiQZ_UTp1HVZNBgNp2-LfvgSHa1DgXXX7zBtDBkibNQZ3r8oX1BqOOYdCqcYyw2E62WuYpKU4eCaHr4y3N-9n3HxNqIxk970NNoq_p7GLLqKlrY_5_jAGJJ32sZWtENPLnF7Sy6ZexqANZBNKJSR0NOdXnKjxHOoG4DZjBqmXnL9EW_1OrzNOl1KHxg.m3nY1-nQCjKxsYlDbvqX6g"
            }
        ]
    }
}
```