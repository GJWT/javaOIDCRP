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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.SerializationException;
import org.oidc.rp.http.HttpClientWrapper;
import org.oidc.rp.oauth2.Client;
import org.oidc.service.Service;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.oidc.ProviderInfoDiscovery;
import org.oidc.service.oidc.Registration;
import org.oidc.service.oidc.Webfinger;
import org.oidc.service.util.Constants;

public class RPHandler {
  
  private String issuer;
  
  private List<ServiceConfig> services;
  
  private Client client;
  
  public RPHandler(String issuer, List<ServiceConfig> services) {
    this.services = services;
    this.issuer = issuer;
  }

  public void begin(String issuer, String userId) throws MissingRequiredAttributeException {
    client = setupClient(issuer, userId);
  }
  
  protected Client setupClient(String issuer, String userId) throws MissingRequiredAttributeException {
    ServiceContext serviceContext = new ServiceContext();
    if (issuer == null) {
      if (userId == null) {
        throw new MissingRequiredAttributeException("Either issuer or userId must be provided");
      }
      Service webfinger = getService(ServiceName.WEBFINGER, serviceContext);
      if (webfinger != null) {
        getIssuerViaWebfinger(webfinger, userId);
        if (serviceContext.getIssuer() != null) {
          this.issuer = serviceContext.getIssuer();
        } else {
          throw new MissingRequiredAttributeException("Could not resolve the issuer for userId=" + userId);
        }
      } else {
        throw new MissingRequiredAttributeException("Webfinger service must be configured if no issuer is provided");        
      }
      Service providerInfoDiscovery = getService(ServiceName.PROVIDER_INFO_DISCOVERY, serviceContext);
      if (providerInfoDiscovery != null) {
        fetchIssuerConfiguration(providerInfoDiscovery);
      } else {
        throw new MissingRequiredAttributeException("ProviderInfoDiscovery service must be configured");
      }
      //TODO: continue the sequence
    }
    Client client = new Client();
    client.setServiceContext(serviceContext);
    return client;
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
  
  protected Service getService(ServiceName serviceName, ServiceContext serviceContext) {
    for (ServiceConfig serviceConfig : services) {
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
        //TODO support other services
      }
    }
    return null;
  }
  
  public Client getClient() {
    return client;
  }
}
