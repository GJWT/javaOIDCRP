# javaOIDCRP

NOTE: Work in progress.

## Introduction

The Relying Party (RP) handler can be used for handling user authentication and access authorization via [OpenID Connect (OIDC)](http://openid.net/specs/openid-connect-core-1_0.html) Providers (OP) or [OAuth2](https://tools.ietf.org/html/rfc6749) Authorization Servers (AS).

This library allow us to:
* Configure the set of services corresponding to the remote OP/AS capabilities:
  1. Provider discovery (Webfinger) - to find out which OP/AS to talk to.
  1. Provider info discovery - to gather information about the OP/AS.
  1. Client registration - to dynamically register RP details to OP/AS.
  1. Authorization/Authentication - done by the user at the OP/AS.
  1. Access token - to obtain access token.
  1. User info - to obtain user claims via access token.
* Use simple Tier 1 API or more controllable Tier 2 API to interact with any OP/AS.

## OP configuration(s) for the RP handler

Clearly the easiest way to configure the OPs for the RP handler is to do it via JSON files. The configuration file format in high level is the following:

```json
{
    "opId_1" : {
        "OP_CONFIGURATION HERE"
    },
    "opId_2" : {
        "OP_CONFIGURATION HERE"
    },

    "opId_n" : {
        "OP_CONFIGURATION HERE"
    }
}
```

With opId\_1, \_2, ..., \_n being nick names for the OP configurations existing as in their values. OP configurations may contain the following values, redirect\_uris and services being the always mandatory, some others depend on the other configuration parameters:

* *issuer*: The OP issuer identifier as JSON string. Mandatory if the Webfinger service is not configured.

* *redirect_uris*: The redirect URIs for the RP as JSON array: a set of URLs from which the RP can chose one to be added to the authorization request. The expectation is that the OP/AS will redirect the use back to this URL after the authorization/authentication has completed.

* *client_id*: The client\_id to be used with this OP as JSON string. Mandatory if the Registration service is not configured.

* *client_secret*: The client\_secret to be used with this OP as JSON string.

* *client_prefs*: The client preferences as defined in [OpenID Connect Dynamic Client Registration 1.0 - Client Metadata](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata). Used in the request message for the Registration service if it is configured, or as desired behaviour parameters if the Registration is not configured.

* *allow*: The list of boolean flags to allow non-standard behaviour from the OP. If there is a deviation from the standard as to how the OP/AS behaves this gives you the possibility to say you are OK with the deviation. Presently there is only one thing you can allow and that is the issuer in the provider info is not the same as the URL you used to fetch the information.

* *services*: The list of services supported by this OP together with their corresponding configurations.

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

The high level methods you have access to (in the order they are to be used) are:

* RPHandler.begin(issuer, userId)
* RPHandler.finalize(issuer, urlEncodedResponseBody)

### begin()

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

The final System.out.println() -line should print something as the following to the standard out:

```
User should be redirected to: https://accounts.google.com/o/oauth2/v2/auth?scope=openid+profile+email&response_type=code&redirect_uri=https%3A%2F%2F127.0.0.1%3A8443%2FjavaOIDCRP-example-app%2Fgoogle%2Fcallback&state=XdzfYz0SFMlKkTJumNUsZTsr5sfCb4xuXBj2CFtB_Hw&nonce=MdTAXjYfXuzC4gS0pp006KeicN2GI8exlC8WljlwrgQ&client_id=xxxxxxxxx.apps.googleusercontent.com
```


What happens next is that the user must be redirected to the URL shown above.

### finalize()

After the user has authenticated at OP/AS, handled consent and access management, the user will be redirect back to the URL provided as value to the redirect_uri parameter in the authentication request. The query part may look something like this:

```
state=Oh3w3gKlvoM2ehFqlxI3HIK5&scope=openid+profile+email&code=Z0FBQUFBQmFkdFFjUVpFWE81SHU5N1N4N01&iss=https%3A%2F%2Faccounts.google.com%2Fop&client_id=xxxxxxxxx.apps.googleusercontent.com
```

It's up to the application to decide how to implement the endpoint and read the response message, but a simplified example with HttpServlets looks as follows. The servlet class is assumed the have access to the same rpHandler object that was used in the previous step. RPHandler's finalize() method does most of the work: depending on the *response_type* and OP/AS configuration, it contacts access token and user info services and combines their responses inside the returned *org.oidc.rp.FinalizeResponse* object.

```java
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.oidc.rp.FinalizeResponse;
import org.oidc.rp.RPHandler;
import org.oidc.service.data.StateRecord;

...

    public void service(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {

      String state = request.getParameter("state");
      StateRecord stateRecord = rpHandler.getStateDb().getState(state);
    
      try {
        FinalizeResponse resp = rpHandler.finalize((String) stateRecord.getClaims().get("iss"), 
          request.getRequestURL() + "?" + request.getQueryString());
        if (resp.indicatesError()) {
          System.out.println("Error response with code: " + resp.getErrorCode());
        } else {
          System.out.println("Authentication succeeded, got the following claims:");
          OpenIDSchema userClaims = resp.getUserClaims();
          for (String key:userClaims.getClaims().keySet()) {
            System.out.println("- " + key + " = " + userClaims.getClaims().get(key));
          }
          System.out.println("Access token: " + resp.getAccessToken());
        }
      } catch (Exception e) {
        throw new ServletException(e.getMessage(), e);
      }
    }
...
    
```

A successful authentication should produce something as the following to the standard out:

```
Authentication succeeded, got the following claims:
- iss = https://accounts.google.com
- azp = xxxxxxxxx.apps.googleusercontent.com
- aud = [xxxxxxxxx.apps.googleusercontent.com]
- sub = 111222333
- email = someones.email.address@gmail.com
- email_verified = true
- at_hash = bal6Rw4QwzKLw_jsssdof2
- nonce = BtT-Gz-SbkjfksksndnffaflMh-J2zmFP28FgXWvWcqiF0
- name = Somebody Surname
- picture = https://lh6.googleusercontent.com/-QW_aP9SXTek/AAAAAAAAAAI/AAAAAAAAAAA/AKxrwcZy12345KaSfDaSdLhwBgUlPbthdg/mo/photo.jpg
- given_name = Somebody
- family_name = Surname
- locale = en
- iat = Mon Jan 07 16:51:01 EET 2019
- exp = Mon Jan 07 17:51:01 EET 2019
- profile = https://profiles.google.com/111222333
Access token: ya29.Glu123754-o3rwMrtbGZI5n3333e6taRsCo3w66666prWOhOmC41-k10C1212bZcKM_7gvLxxxxxr-P9y3aCdBXc9bzSyRrs_kHBo9dsfjofdsjp
```

The returned instance of *org.oidc.rp.FinalizeResponse* thus provides all the user claims together with possible access and refresh tokens. The user claims are combined from the *id_token* and possible user info endpoint claims, but those can also be fetched from the state database in the following way:

```java
import org.oidc.common.MessageType;
import org.oidc.msg.oidc.IDToken;
import org.oidc.msg.oidc.OpenIDSchema;

...

    IDToken idToken = (IDToken) rpHandler.getStateDb().getItem(state, MessageType.VERIFIED_IDTOKEN);
    OpenIDSchema userInfo = rpHandler.getStateDb().getItem(state, MessageType.OpenIDSchema);

...
    
```
