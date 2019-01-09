/*
 * Copyright (C) 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.oidc.rp;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oauth2.ResponseMessage;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.msg.oidc.IDToken;
import org.oidc.msg.oidc.OpenIDSchema;
import org.oidc.msg.oidc.RegistrationRequest;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.rp.config.OpConfiguration;
import org.oidc.rp.http.HttpClientWrapper;
import org.oidc.rp.oauth2.Client;
import org.oidc.service.Service;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.data.InMemoryStateImpl;
import org.oidc.service.data.State;
import org.oidc.service.oidc.AccessToken;
import org.oidc.service.oidc.Authentication;
import org.oidc.service.oidc.ProviderInfoDiscovery;
import org.oidc.service.oidc.Registration;
import org.oidc.service.oidc.UserInfo;
import org.oidc.service.oidc.Webfinger;
import org.oidc.service.util.Constants;

public class RPHandler {

  private OpConfiguration opConfiguration;

  private Client client;

  /** State db for storing messages. */
  private State stateDb;

  /** Maps issuer to correct client. */
  private Map<String, Client> issuer2Client = new HashMap<String, Client>();

  public RPHandler(OpConfiguration configuration) {
    this(configuration, new InMemoryStateImpl());
  }

  public RPHandler(OpConfiguration configuration, State stateDb) {
    this.opConfiguration = configuration;
    this.stateDb = stateDb;
  }

  public BeginResponse begin(String issuer, String userId)
      throws MissingRequiredAttributeException, UnsupportedSerializationTypeException,
      RequestArgumentProcessingException, SerializationException, ValueException, 
      InvalidClaimException {
    client = setupClient(issuer, userId);
    boolean authorizationExists = false;
    for (ServiceConfig serviceConfig : opConfiguration.getServiceConfigs()) {
      if (ServiceName.AUTHORIZATION.equals(serviceConfig.getServiceName())) {
        authorizationExists = true;
      }
    }
    if (!authorizationExists) {
      return new BeginResponse(null, null);
    }
    return initializeAuthentication(client);
  }

  protected Message getAccessTokenResponse(String state, Client client) 
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {
    // This method should visit the token endpoint, verify the response message and id token
    // possibly contained by it.
    Map<String, Object> requestArguments = new HashMap<String, Object>();
    requestArguments.put("state", state);
    Service accessToken = getService(ServiceName.ACCESS_TOKEN, client.getServiceContext());
    callRemoteService(accessToken, requestArguments, state);
    return accessToken.getResponseMessage();
  }

  protected ResolveTokensResponse resolveTokens(AuthenticationResponse authenticationResponse,
      String state, Client client)
          throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
          RequestArgumentProcessingException {
    AuthenticationRequest request = (AuthenticationRequest) stateDb.getItem(state,
        MessageType.AUTHORIZATION_REQUEST);
    String responseTypes = (String) request.getClaims().get("response_type");
    // if response_type contains id_token we should have it in authentication response
    IDToken idToken = null;
    String accessToken = null;
    String refreshToken = null;
    if (Pattern.compile("\\bid_token\\b").matcher(responseTypes).find()
        && authenticationResponse.getVerifiedIdToken() != null) {
      idToken = authenticationResponse.getVerifiedIdToken();
    }
    if (Pattern.compile("\\btoken\\b").matcher(responseTypes).find()
        && authenticationResponse.getClaims().containsKey("access_token")) {
      accessToken = (String) authenticationResponse.getClaims().get("access_token");
    }
    // Having no id token at this point or having code in response type but not having access
    // token implies need to visit token endpoint..
    if (idToken == null
        || (accessToken == null && Pattern.compile("\\bcode\\b").matcher(responseTypes).find())) {
      Message response = getAccessTokenResponse(state, client);
      if (((ResponseMessage) response).indicatesErrorResponseMessage()) {
        return new ResolveTokensResponse((String) response.getClaims().get("state"),
            (String) response.getClaims().get("error"),
            (String) response.getClaims().get("error_description"),
            (String) response.getClaims().get("error_uri"));
      }
      AccessTokenResponse accessTokenResponse = (AccessTokenResponse) response;
      accessToken = (String) accessTokenResponse.getClaims().get("access_token");
      refreshToken = (String) accessTokenResponse.getClaims().get("refresh_token");
      if (accessTokenResponse.getVerifiedIdToken() != null) {
        idToken = accessTokenResponse.getVerifiedIdToken();
      }
    }
    return new ResolveTokensResponse(idToken, accessToken, refreshToken);
  }

  public FinalizeResponse finalize(String issuer, String urlEncodedResponseBody)
      throws MissingRequiredAttributeException, DeserializationException, ValueException,
      InvalidClaimException, RequestArgumentProcessingException {

    Client client = issuer2Client.get(issuer);
    if (client == null) {
      throw new MissingRequiredAttributeException("Could not resolve client for the issuer");
    }
    ResponseMessage response = finalizeAuthentication(client, issuer, urlEncodedResponseBody);
    if (response.indicatesErrorResponseMessage()) {
      return new FinalizeResponse((String) response.getClaims().get("state"),
          (String) response.getClaims().get("error"),
          (String) response.getClaims().get("error_description"),
          (String) response.getClaims().get("error_uri"));
    }
    AuthenticationResponse authenticationResponse = (AuthenticationResponse) response;
    String state = (String) authenticationResponse.getClaims().get("state");
    ResolveTokensResponse resp = resolveTokens(authenticationResponse, state, client);
    if (resp.indicatesError()) {
      return new FinalizeResponse((AbstractResponse) resp);
    }
    OpenIDSchema userClaims = new OpenIDSchema(resp.getIDToken().getClaims());
    // If there is userinfo endpoint, we look for more claims
    UserInfo service = (UserInfo) getService(ServiceName.USER_INFO, client.getServiceContext());
    if (service != null && resp.getAccessToken() != null) {
      Map<String, Object> requestArguments = new HashMap<String, Object>();
      requestArguments.put("access_token", resp.getAccessToken());
      callRemoteService(service, requestArguments, state);
      OpenIDSchema userInfoClaims = (OpenIDSchema) service.getResponseMessage();
      if (userInfoClaims.indicatesErrorResponseMessage()) {
        return new FinalizeResponse(state, (String) userInfoClaims.getClaims().get("error"),
            (String) userInfoClaims.getClaims().get("error_description"),
            (String) userInfoClaims.getClaims().get("error_uri"));
      }
      userClaims.getClaims().putAll(userInfoClaims.getClaims());
    }
    return new FinalizeResponse(state, userClaims, resp.getAccessToken(), resp.getRefreshToken());
  }

  protected ResponseMessage finalizeAuthentication(Client client, String issuer,
      String urlEncodedResponseBody) throws DeserializationException, ValueException,
      InvalidClaimException, MissingRequiredAttributeException {

    Service service = getService(ServiceName.AUTHORIZATION, client.getServiceContext());
    ResponseMessage response = (AuthenticationResponse) service
        .parseResponse(urlEncodedResponseBody);
    if (response.indicatesErrorResponseMessage()) {
      return response;
    }
    AuthenticationResponse authenticationResponse = (AuthenticationResponse) response;
    String state = (String) authenticationResponse.getClaims().get("state");
    String issuerByState = getStateDb().getIssuer(state);
    if (issuerByState == null) {
      throw new ValueException(String.format("Could not resolve issuer for state '%s'", state));
    }
    if (!issuerByState.equals(issuer)) {
      throw new ValueException(
          String.format("Issuer mismatch, '%s' != '%s'", issuerByState, issuer));
    }
    service.updateServiceContext(authenticationResponse, state);
    return authenticationResponse;
  }

  protected Client setupClient(String issuer, String userId)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {

    // See if the client has been stored already by issuer
    if (issuer != null || opConfiguration.getServiceContext().getIssuer() != null) {
      issuer = issuer == null ? opConfiguration.getServiceContext().getIssuer() : issuer;
      Client client = issuer2Client.get(issuer);
      if (client != null) {
        return client;
      }
    }
    // No prestored client, we try to perform webfinger and register the client.
    if (issuer == null && userId == null) {
      throw new MissingRequiredAttributeException("Either issuer or userId must be provided");
    }
    if (issuer == null) {
      // Webfinger only if issuer is not given
      Service webfinger = getService(ServiceName.WEBFINGER, opConfiguration.getServiceContext());
      if (webfinger != null) {
        Map<String, Object> requestParams = new HashMap<>();
        requestParams.put(Constants.WEBFINGER_RESOURCE, userId);
        callRemoteService(webfinger, requestParams, null);
        if (opConfiguration.getServiceContext().getIssuer() == null) {
          throw new MissingRequiredAttributeException(
              "Could not resolve the issuer for userId=" + userId);
        }
      } else {
        throw new MissingRequiredAttributeException(
            "Webfinger service must be configured if no issuer is provided");
      }
    }
    Service providerInfoDiscovery = getService(ServiceName.PROVIDER_INFO_DISCOVERY,
        opConfiguration.getServiceContext());
    if (providerInfoDiscovery != null) {
      callRemoteService(providerInfoDiscovery, null);
    } else {
      throw new MissingRequiredAttributeException(
          "ProviderInfoDiscovery service must be configured to fetch configuration for "
          + opConfiguration.getServiceContext().getIssuer());
    }
    Service registration = getService(ServiceName.REGISTRATION,
        opConfiguration.getServiceContext());
    if (registration != null) {
      callRemoteService(registration, null);
    } else {
      RegistrationRequest preferences = opConfiguration.getServiceContext().getClientPreferences();
      RegistrationResponse behaviour = preferences == null ? 
          new RegistrationResponse() : new RegistrationResponse(preferences.getClaims());
      behaviour.addClaim("client_id", opConfiguration.getServiceContext().getClientId());
      behaviour.addClaim("client_secret", opConfiguration.getServiceContext().getClientSecret());
      behaviour.addClaim("redirect_uris", opConfiguration.getServiceContext().getRedirectUris());
      opConfiguration.getServiceContext().setBehavior(behaviour);
    }
    Client client = new Client();
    client.setServiceContext(opConfiguration.getServiceContext());
    // We store registered client
    issuer2Client.put(opConfiguration.getServiceContext().getIssuer(), client);
    return client;
  }

  /**
   * Constructs the URL that will redirect the user to the authentication endpoint of the OP /
   * authorization endpoint of the AS.
   * 
   * @param client
   *          Client instance, having service context for configuring the request.
   * @return url for authentication/authorization endpoint and state parameter.
   * @throws MissingRequiredAttributeException
   *           if both client and state are null.
   * @throws SerializationException
   * @throws RequestArgumentProcessingException
   * @throws UnsupportedSerializationTypeException
   */
  protected BeginResponse initializeAuthentication(Client client)
      throws MissingRequiredAttributeException, UnsupportedSerializationTypeException,
      RequestArgumentProcessingException, SerializationException {

    if (client == null) {
      throw new MissingRequiredAttributeException("Client or state must be provided");
    }
    Map<String, Object> defaultRequestArguments = new HashMap<String, Object>();
    RegistrationResponse behavior = client.getServiceContext().getBehavior();
    if (behavior != null) {
      // by default we request for all scopes
      if (behavior.getClaims().containsKey("scope")) {
        defaultRequestArguments.put("scope", behavior.getClaims().get("scope"));
      }
    }
    String state = stateDb.createStateRecord(client.getServiceContext().getIssuer(),
        (String) defaultRequestArguments.get("state"));
    return new BeginResponse(getService(ServiceName.AUTHORIZATION, client.getServiceContext())
        .getRequestParameters(defaultRequestArguments).getUrl(), state);
  }

  protected void callRemoteService(Service service, String state)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {
    callRemoteService(service, new HashMap<String, Object>(), state);
  }
  
  protected void callRemoteService(Service service, Map<String, Object> requestArguments, 
      String state) 
          throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
          RequestArgumentProcessingException {
    try {
      HttpArguments httpArguments = service.getRequestParameters(requestArguments);
      HttpClientWrapper.doRequest(httpArguments, service, state);
    } catch (UnsupportedSerializationTypeException | SerializationException | IOException e) {
      throw new ValueException("Could not communicate with the remote server", e);
    }
  }

  protected Service getService(ServiceName serviceName, ServiceContext serviceContext) {
    for (ServiceConfig serviceConfig : opConfiguration.getServiceConfigs()) {
      if (serviceName.equals(serviceConfig.getServiceName())) {
        if (ServiceName.WEBFINGER.equals(serviceName)) {
          return new Webfinger(serviceContext, serviceConfig);
        }
        if (ServiceName.PROVIDER_INFO_DISCOVERY.equals(serviceName)) {
          return new ProviderInfoDiscovery(serviceContext, null, serviceConfig);
        }
        if (ServiceName.REGISTRATION.equals(serviceName)) {
          return new Registration(serviceContext, null, serviceConfig);
        }
        if (ServiceName.AUTHORIZATION.equals(serviceName)) {
          return new Authentication(serviceContext, stateDb, serviceConfig);
        }
        if (ServiceName.ACCESS_TOKEN.equals(serviceName)) {
          return new AccessToken(serviceContext, stateDb, serviceConfig);
        }
        if (ServiceName.USER_INFO.equals(serviceName)) {
          return new UserInfo(serviceContext, stateDb, serviceConfig);
        }
      }
    }
    return null;
  }

  public Client getClient() {
    return client;
  }

  public State getStateDb() {
    return stateDb;
  }

  public OpConfiguration getOpConfiguration() {
    return opConfiguration;
  }

}
