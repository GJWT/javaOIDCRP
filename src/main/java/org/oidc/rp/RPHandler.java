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

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.SerializationException;
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
import org.oidc.service.oidc.Authentication;
import org.oidc.service.oidc.ProviderInfoDiscovery;
import org.oidc.service.oidc.Registration;
import org.oidc.service.oidc.Webfinger;
import org.oidc.service.util.Constants;

public class RPHandler {

  private OpConfiguration opConfiguration;
  
  private Client client;

  /** State db for storing messages. */
  private State stateDb;

  public RPHandler(OpConfiguration configuration) {
    this(configuration, new InMemoryStateImpl());
  }

  public RPHandler(OpConfiguration configuration, State stateDb) {
    this.opConfiguration = configuration;
    this.stateDb = stateDb;
  }

  public List<String> begin(String issuer, String userId)
      throws MissingRequiredAttributeException, UnsupportedSerializationTypeException,
      RequestArgumentProcessingException, SerializationException {
    client = setupClient(issuer, userId);
    // TODO: Do we ever need to set state or requestArguments?
    return initializeAuthentication(client, null, null);
  }

  protected Client setupClient(String issuer, String userId)
      throws MissingRequiredAttributeException {
    if (issuer == null && opConfiguration.getServiceContext().getIssuer() == null) {
      if (userId == null) {
        throw new MissingRequiredAttributeException("Either issuer or userId must be provided");
      }
      Service webfinger = getService(ServiceName.WEBFINGER, opConfiguration.getServiceContext());
      if (webfinger != null) {
        getIssuerViaWebfinger(webfinger, userId);
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
      fetchIssuerConfiguration(providerInfoDiscovery);
    } else {
      throw new MissingRequiredAttributeException(
          "ProviderInfoDiscovery service must be configured");
    }
    Service registration = getService(ServiceName.REGISTRATION, opConfiguration.getServiceContext());
    if (registration != null) {
      doDynamicRegistration(registration);
    }
    // TODO: continue the sequence
    Client client = new Client();
    client.setServiceContext(opConfiguration.getServiceContext());
    return client;
  }

  /**
   * Constructs the URL that will redirect the user to the authentication endpoint of the OP /
   * authorization endpoint of the AS.
   * 
   * @param client
   *          Client instance, having service context for configuring the request.
   * @param state
   *          For fetching existing client instance if client is set as null.
   * @param requestArguments
   *          Non-default request arguments.
   * @return List of strings, first value is url for authentication/authorization endpoint, second
   *         value is state parameter.
   * @throws MissingRequiredAttributeException
   *           if both client and state are null.
   * @throws SerializationException
   * @throws RequestArgumentProcessingException
   * @throws UnsupportedSerializationTypeException
   */
  @SuppressWarnings("unchecked")
  protected List<String> initializeAuthentication(Client client, String state,
      Map<String, Object> requestArguments)
      throws MissingRequiredAttributeException, UnsupportedSerializationTypeException,
      RequestArgumentProcessingException, SerializationException {

    if (client == null) {
      if (state == null) {
        throw new MissingRequiredAttributeException("Either client or state must be provided");
      }
      // TODO: way to store client per state key and fetch it here
      throw new MissingRequiredAttributeException("Fetching client by state not implemented yet");
    }
    // Set default arguments nonce, redirect_uri, scope and response type
    Map<String, Object> defaultRequestArguments = new HashMap<String, Object>();
    // Set client_id
    defaultRequestArguments.put("client_id", client.getServiceContext().getClientId());
    // Set nonce
    // TODO: create project util for creating state/nonce
    byte[] rand = new byte[32];
    new SecureRandom().nextBytes(rand);
    defaultRequestArguments.put("nonce", Base64.getUrlEncoder().encodeToString(rand));
    // Set redirect_uri
    if (client.getServiceContext().getRedirectUris() != null
        && client.getServiceContext().getRedirectUris().size() > 0) {
      defaultRequestArguments.put("redirect_uri",
          client.getServiceContext().getRedirectUris().get(0));
    }
    RegistrationResponse behavior = client.getServiceContext().getBehavior();
    if (behavior != null) {
      // set scope
      if (behavior.getClaims().containsKey("scope")) {
        defaultRequestArguments.put("scope", behavior.getClaims().get("scope"));
      }
      // Set response type
      if (behavior.getClaims().containsKey("response_types")) {
        defaultRequestArguments.put("response_type",
            (String) ((List<String>) behavior.getClaims().get("response_types")).get(0));
      }
    }

    // Set non-default request arguments
    if (requestArguments != null) {
      defaultRequestArguments.putAll(requestArguments);
    }
    state = stateDb.createStateRecord(client.getServiceContext().getIssuer(), state);
    defaultRequestArguments.put("state", state);
    stateDb.storeStateKeyForNonce((String) defaultRequestArguments.get("nonce"), state);
    List<String> uriAndState = new ArrayList<String>();
    uriAndState.add(getService(ServiceName.AUTHORIZATION, client.getServiceContext())
        .getRequestParameters(defaultRequestArguments).getUrl());
    uriAndState.add(state);
    return uriAndState;
  }

  protected void getIssuerViaWebfinger(Service webfinger, String resource) {
    Map<String, Object> requestParams = new HashMap<>();
    requestParams.put(Constants.WEBFINGER_RESOURCE, resource);
    try {
      HttpArguments httpArguments = webfinger.getRequestParameters(requestParams);
      HttpClientWrapper.doRequest(httpArguments, webfinger);
    } catch (UnsupportedSerializationTypeException | RequestArgumentProcessingException
        | SerializationException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  protected void fetchIssuerConfiguration(Service providerInfoDiscovery) {
    try {
      HttpArguments httpArguments = providerInfoDiscovery.getRequestParameters(null);
      HttpClientWrapper.doRequest(httpArguments, providerInfoDiscovery);
    } catch (UnsupportedSerializationTypeException | RequestArgumentProcessingException
        | SerializationException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

  protected void doDynamicRegistration(Service registration) {
    try {
      Map<String, Object> requestArguments = new HashMap<>();
      HttpArguments httpArguments = registration.getRequestParameters(requestArguments);
      HttpClientWrapper.doRequest(httpArguments, registration);
    } catch (UnsupportedSerializationTypeException | RequestArgumentProcessingException
        | SerializationException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
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
        // TODO support other services
      }
    }
    return null;
  }

  public Client getClient() {
    return client;
  }
}
