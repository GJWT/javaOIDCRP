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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
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

import com.google.common.base.Strings;

/**
 * The Relying Party (RP) handler can be used for handling user authentication and access
 * authorization via OpenID Connect (OIDC) Providers (OP) or OAuth2 Authorization Servers (AS).
 */
public class RPHandler {

  /** The configurations for the remote AS/OPs. */
  private List<OpConfiguration> opConfigurations;

  /** The state db for storing messages between the RP and the remote AS/OP. */
  private State stateDb;

  /** Maps issuer to correct client. */
  private Map<String, Client> issuer2Client = new HashMap<String, Client>();
  
  /**
   * Constructor. Uses default state db.
   * 
   * @param configurations The configurations for the remote AS/OPs.
   */
  public RPHandler(List<OpConfiguration> configurations) {
    this(configurations, new InMemoryStateImpl());
  }
  
  /**
   * Constructor. Uses default state db.
   * 
   * @param configuration The configuration for the remote AS/OP.
   */
  public RPHandler(OpConfiguration configuration) {
    this(Arrays.asList(configuration));
  }

  /**
   * Constructor.
   * 
   * @param configurations The configurations for the remote AS/OPs.
   * @param stateDb The state db for storing messages between the RP and the remote AS/OP.
   */
  public RPHandler(List<OpConfiguration> configurations, State stateDb) {
    this.opConfigurations = configurations;
    this.stateDb = stateDb;
  }
  
  /**
   * Constructor.
   * 
   * @param configuration The configuration for the remote AS/OP.
   * @param stateDb The state db for storing messages between the RP and the remote AS/OP.
   */
  public RPHandler(OpConfiguration configuration, State stateDb) {
    this(Arrays.asList(configuration), stateDb);
  }

  /**
   * Begins the authentication sequence. If configured and needed, Webfinger, 
   * ProviderInfoDiscovery and Registration services are called before constructing the request
   * message for the Authorization service. Either issuer or userId must be given in the
   * parameters.
   * 
   * @param issuer The issuer of the AS/OP to be called.
   * @param userId The userId to be used for the Webfinger service.
   * @return The details for the request to be sent to the Authorization service.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the communication with any service fails.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
  public BeginResponse begin(String issuer, String userId)
      throws MissingRequiredAttributeException, RequestArgumentProcessingException, ValueException,
      InvalidClaimException {
    Client client = setupClient(issuer, userId);
    if (authorizationServiceExists(client)) {
      return initializeAuthentication(client);
    } else {
      return new BeginResponse(null, null);
    }
  }
  
  /**
   * Checks if the Authorization service is configured for the OP for the given client.
   * 
   * @param client The client whose OP configuration is checked.
   * @return true if Authorization service is configured, false otherwise.
   */
  protected boolean authorizationServiceExists(Client client) {
    for (ServiceConfig serviceConfig : client.getOpConfiguration().getServiceConfigs()) {
      if (ServiceName.AUTHORIZATION.equals(serviceConfig.getServiceName())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Calls the access token service with the given state.
   * 
   * @param state The state to be used when calling the service.
   * @param client The client where to get the OP configuration.
   * @return The response message obtained from the access token service.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the communication with any service fails.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
  protected Message getAccessTokenResponse(String state, Client client) 
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {
    // This method should visit the token endpoint, verify the response message and id token
    // possibly contained by it.
    Map<String, Object> requestArguments = new HashMap<String, Object>();
    requestArguments.put("state", state);
    Service accessToken = getService(client.getOpConfiguration(), ServiceName.ACCESS_TOKEN);
    if (accessToken == null) {
      throw new ValueException("Access token service is not configured for the given client");
    }
    callRemoteService(accessToken, requestArguments, state);
    return accessToken.getResponseMessage();
  }

  /**
   * Resolves the tokens from the given authentication response, or possibly further call the
   * access token service.
   * 
   * @param authenticationResponse The message from which to exploit id_token and access tokens.
   * @param state The state to be used in the access token service call.
   * @param client The client where to get the OP configuration.
   * @return The resolved token details.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the communication with any service fails.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
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

  /**
   * Finalizes the authentication for the given issuer with the given authentication response
   * message.
   * 
   * @param issuer The issuer from which the response is coming from.
   * @param urlEncodedResponseBody The serialized response message from the OP.
   * @return The authentication details.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute or
   *        the client corresponding to the given issuer cannot be found.
   * @throws DeserializationException If the given response message cannot be deserialized.
   * @throws ValueException If the communication with any service fails.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
  public FinalizeResponse finalize(String issuer, String urlEncodedResponseBody)
      throws MissingRequiredAttributeException, DeserializationException, ValueException,
      InvalidClaimException, RequestArgumentProcessingException {

    Client client = getClient(issuer);
    if (client == null) {
      throw new MissingRequiredAttributeException("Could not resolve client for the issuer " 
          + issuer);
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
    UserInfo service = (UserInfo) getService(client.getOpConfiguration(), ServiceName.USER_INFO);
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

  /**
   * Finalizes the authentication for the given issuer with the given authentication response
   * message, using the given client.
   * 
   * @param issuer The issuer from which the response is coming from.
   * @param urlEncodedResponseBody The serialized response message from the OP.
   * @param client The client where to get the OP configuration.
   * @return The authentication details.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute or
   *        the client corresponding to the given issuer cannot be found.
   * @throws DeserializationException If the given response message cannot be deserialized.
   * @throws ValueException If the communication with any service fails.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
  protected ResponseMessage finalizeAuthentication(Client client, String issuer,
      String urlEncodedResponseBody) throws DeserializationException, ValueException,
      InvalidClaimException, MissingRequiredAttributeException {

    Service service = getService(client.getOpConfiguration(), ServiceName.AUTHORIZATION);
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

  /**
   * Calls the Webfinger services of all the configured OPs in order to find an issuer that could
   * authenticate the given user identifier. Finally its corresponding configuration is returned.
   * 
   * @param userId The user identifier whose authenticator is searched via Webfinger.
   * @return The issuer configuration of the OP who can authenticate the user.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the communication with any service fails, if the issuer could not
   *        be resolved or the configuration corresponding to the issuer is not found.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
  protected OpConfiguration callWebfingerServices(String userId) throws 
      MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {
    for (OpConfiguration opConfiguration : opConfigurations) {
      Service webfinger = getService(opConfiguration, ServiceName.WEBFINGER);
      if (webfinger != null) {
        Map<String, Object> requestParams = new HashMap<>();
        requestParams.put(Constants.WEBFINGER_RESOURCE, userId);
        callRemoteService(webfinger, requestParams, null);
        String resolvedIssuer = opConfiguration.getServiceContext().getIssuer();
        if (resolvedIssuer != null) {
          OpConfiguration resolvedConfig = getOpConfigurationViaIssuer(resolvedIssuer);
          if (resolvedConfig != null) {
            return resolvedConfig;
          }
        }
      }
    }
    throw new ValueException("Could not resolve the issuer configuration for userId=" + userId);
  }

  /**
   * Sets up the client for the communication with OP. If configured and needed, Webfinger, 
   * ProviderInfoDiscovery and Registration services are called before. Either issuer or userId
   * must be given in the parameters.
   * 
   * @param issuer The issuer of the AS/OP to be called.
   * @param userId The userId to be used for the Webfinger service.
   * @return The details for the request to be sent to the Authorization service.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the communication with any service fails.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
  protected Client setupClient(String issuer, String userId)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {

    // See if the client has been stored already by issuer
    if (issuer != null) {
      Client client = getClient(issuer);
      if (client != null) {
        return client;
      }
    }
    if (issuer == null && userId == null) {
      throw new MissingRequiredAttributeException("Either issuer or userId must be provided");
    }
    // No prestored client, we try to perform webfinger and register the client.
    OpConfiguration opConfiguration;
    if (issuer == null) {
      // Webfinger only if issuer is not given
      opConfiguration = callWebfingerServices(userId);
    } else {
      opConfiguration = getOpConfigurationViaIssuer(issuer);
      if (opConfiguration == null) {
        throw new ValueException(
            "Could not find OP configuration for the given issuer " + issuer);
      }
    }
    Service providerInfoDiscovery = getService(opConfiguration, 
        ServiceName.PROVIDER_INFO_DISCOVERY);
    if (providerInfoDiscovery != null) {
      callRemoteService(providerInfoDiscovery, null);
    } else {
      throw new MissingRequiredAttributeException(
          "ProviderInfoDiscovery service must be configured to fetch configuration for "
          + opConfiguration.getServiceContext().getIssuer());
    }
    Service registration = getService(opConfiguration, ServiceName.REGISTRATION);
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
    Client client = new Client(opConfiguration);
    // We store registered client
    storeClient(opConfiguration.getServiceContext().getIssuer(), client);
    return client;
  }

  /**
   * Constructs the URL that will redirect the user to the authentication endpoint of the OP /
   * authorization endpoint of the AS.
   * 
   * @param client Client instance, having service context for configuring the request.
   * @return url for authentication/authorization endpoint and state parameter.
   * @throws MissingRequiredAttributeException if any required attribute is missing.
   * @throws RequestArgumentProcessingException If the request arguments are unexpected.
   * @throws ValueException If the request message cannot be serialized.
   */
  protected BeginResponse initializeAuthentication(Client client)
      throws MissingRequiredAttributeException, RequestArgumentProcessingException,
        ValueException  {

    if (client == null) {
      throw new MissingRequiredAttributeException("Client must be provided");
    }
    Map<String, Object> defaultRequestArguments = new HashMap<String, Object>();
    RegistrationResponse behavior = client.getServiceContext().getBehavior();
    if (behavior != null) {
      // by default we request for all scopes
      if (behavior.getClaims().containsKey("scope")) {
        defaultRequestArguments.put("scope", behavior.getClaims().get("scope"));
      }
    }
    String state = stateDb.createStateRecord(client.getServiceContext().getIssuer(), null);
    
    Service authorization = getService(client.getOpConfiguration(), ServiceName.AUTHORIZATION);
    BeginResponse response;
    try {
      response = new BeginResponse(authorization.getRequestParameters(defaultRequestArguments)
          .getUrl(), state);
    } catch (UnsupportedSerializationTypeException | SerializationException e) {
      throw new ValueException("Could not serialize the request message", e);
    }
    stateDb.storeItem(authorization.getRequestMessage(), state, MessageType.AUTHORIZATION_REQUEST);
    return response;
  }

  /**
   * Calls the given remote service with given state. Also the service context will be updated via
   * {@link Service#updateServiceContext(Message, String) -method.
   * 
   * @param service The service to be called.
   * @param state The state to be used with {@link Service#updateServiceContext(Message, String).
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the communication fails.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
  protected void callRemoteService(Service service, String state)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {
    callRemoteService(service, new HashMap<String, Object>(), state);
  }
  
  /**
   * Calls the given remote service with given arguments and state. Also the service context will
   * be updated via {@link Service#updateServiceContext(Message, String) -method.
   * 
   * @param service The service to be called.
   * @param requestArguments The map of request arguments.
   * @param state The state to be used with {@link Service#updateServiceContext(Message, String).
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the communication fails.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws RequestArgumentProcessingException If the request arguments are invalid.
   */
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

  /**
   * Get the desired service from the given OP configuration.
   * 
   * @param opConfiguration The OP configuration where to fetch the service.
   * @param serviceName The name of the service to be fetched.
   * @return The service, or null if it was not configured for the given OP.
   */
  protected Service getService(OpConfiguration opConfiguration, ServiceName serviceName) {
    ServiceContext serviceContext = opConfiguration.getServiceContext();
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
  
  /**
   * Get the OP configuration corresponding to the given issuer.
   * 
   * @param issuer The issuer corresponding to the desired OP configuration.
   * @return The OP configuration, or null if it was not found.
   */
  protected OpConfiguration getOpConfigurationViaIssuer(String issuer) {
    if (Strings.isNullOrEmpty(issuer)) {
      return null;
    }
    for (OpConfiguration opConfiguration : opConfigurations) {
      if (issuer.equals(opConfiguration.getIssuer())) {
        return opConfiguration;
      }
    }
    return null;
  }

  /**
   * Get the state db for storing messages between the RP and the remote AS/OP.
   * 
   * @return The state db for storing messages between the RP and the remote AS/OP.
   */
  public State getStateDb() {
    return stateDb;
  }

  /**
   * Get the configurations for the remote AS/OPs.
   * 
   * @return The configurations for the remote AS/OPs.
   */
  public List<OpConfiguration> getOpConfigurations() {
    return opConfigurations;
  }
  
  /**
   * Get the stored client for the given issuer.
   * 
   * @param issuer The issuer to get the client to.
   * @return The client corresponding to the issuer, or null if it has not been stored.
   */
  public Client getClient(String issuer) {
    return issuer2Client.get(issuer);
  }
  
  /**
   * Stores the client for the given issuer.
   * 
   * @param issuer The issuer to store the client to.
   * @param client The client corresponding to the issuer.
   */
  public void storeClient(String issuer, Client client) {
    issuer2Client.put(issuer, client);
  }

}