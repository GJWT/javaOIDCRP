# javaOIDCRP

## Introduction

## OP configuration(s) for the RP handler

Clearly the easiest way to configure the OPs for the RP handler is to do it via JSON files. The configuration file format in high level is the following:

```json
{
    "opId_1" : {
        <OP_CONFIGURATION HERE>
    },
    "opId_2" : {
        <OP_CONFIGURATION HERE>
    },
    ...
    "opId_n" : {
        <OP_CONFIGURATION HERE>
    }
}
```

With opId_1, _2, ..., _n being nick names for the OP configurations existing as in their values. OP configurations may contain the following values, redirect_uris and services being the always mandatory, some others depend on the other configuration parameters:

* _issuer_: The OP issuer identifier as JSON string. Mandatory if Webfinger service is not configured.

* _redirect___uris_: The redirect URIs for the RP as JSON array.

* _client___id_: The client_id to be used with this OP as JSON string. Mandatory if Registration service is not configured.

* _client___secret_: The client_secret to be used with this OP as JSON string.

* _client___prefs_: The client preferences, TODO.

* _allow_: The list of boolean flags to allow non-standard behaviour from the OP.

* _services_: The list of services supported by this OP together with their corresponding configurations.

Configuration example for Google's OP:

```json
{
    "google": {
        "issuer": "https://accounts.google.com/",
        "client_id": "xxxxxxxxx.apps.googleusercontent.com",
        "client_secret": "2222222222111111111",
        "redirect_uris": ["${BASEURL}/google/callback"],
        "client_prefs": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": "client_secret_basic"
        },
        "services": {
            "ProviderInfoDiscovery": {},
            "Authorization": {},
            "AccessToken": {},
            "RefreshAccessToken": {},
            "UserInfo": {"default_authn_method": "bearer_body"}
        }
    }
}

```


## RP Handler API

### Tier 1 API

The high level methods you have access to (in the order they are to be used) are:

RPHandler.begin(issuer, userId)

Depending on the service configuration, either issuer or userId is required. If Webfinger is included in the services, then issuer can be left null. Otherwise, issuer must always be defined.

This method will initiate a RP/Client instance if none exists for the OP/AS in question. It will then run service 1 if needed, services 2 and 3 according to configuration and finally will construct the authorization request.

Usage example, with FILE_PATH containing path to the file containing the OP configuration for google as shown in the previous section.

```java
import org.oidc.rp.BeginResponse;
import org.oidc.rp.RPHandler;
import org.oidc.rp.config.OpConfiguration;

...

    String baseUrl = "https://127.0.0.1:8443/javaOIDCRP-example-app";
    Map<String, OpConfiguration> opConfigs = OpConfiguration.parseFromJson("<FILE_PATH>", baseUrl);
    RPHandler rpHandler = new RPHandler(opConfigs.get("google"));
    BeginResponse beginResponse = rpHandler.begin("https://accounts.google.com/", null);
    System.out.println("User should be redirected to: " + beginResponse.getRedirectUri());
...
	
```

```
User should be redirected to: https://accounts.google.com/o/oauth2/v2/auth?scope=openid+profile+email&response_type=code&redirect_uri=https%3A%2F%2F127.0.0.1%3A8443%2FjavaOIDCRP-example-app%2Fgoogle%2Fcallback&state=XdzfYz0SFMlKkTJumNUsZTsr5sfCb4xuXBj2CFtB_Hw&nonce=MdTAXjYfXuzC4gS0pp006KeicN2GI8exlC8WljlwrgQ&client_id=xxxxxxxxx.apps.googleusercontent.com
```


What happens next is that the user must be redirected to the URL shown above. After the user has authenticated, handled consent and access management the user will be redirect back to the URL provided as value to the redirect_uri parameter in the URL above.


#### RPHandler


