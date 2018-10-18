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

package org.oidc.rp.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.oidc.common.ServiceName;
import org.oidc.msg.AbstractMessage;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.ParameterVerificationDefinition;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.RegistrationRequest;
import org.oidc.msg.validator.ClaimValidator;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceConfigMessage;

import com.google.common.collect.ImmutableMap;

public class OpConfigurationsMessage extends AbstractMessage {

  public OpConfigurationsMessage(Map<String, Object> claims) {
    super(claims);
    for (String key : claims.keySet()) {
      paramVerDefs.put(key,
          new ParameterVerificationDefinition(new OpConfigurationValidator(), true));
    }
  }
  
  protected static ServiceName getServiceName(String key) {
    return ImmutableMap.<String, ServiceName>builder()
        .put("ProviderInfoDiscovery", ServiceName.PROVIDER_INFO_DISCOVERY)
        .put("Registration", ServiceName.REGISTRATION).put("Webfinger", ServiceName.WEBFINGER)
        .put("Authorization", ServiceName.AUTHORIZATION)
        .put("AccessToken", ServiceName.ACCESS_TOKEN)
        .put("RefreshAccessToken", ServiceName.REFRESH_ACCESS_TOKEN)
        .put("UserInfo", ServiceName.USER_INFO).build().get(key);
  }

  protected class SingleOpConfiguration extends AbstractMessage {

    {
      paramVerDefs.put("issuer", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
      paramVerDefs.put("client_id", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
      paramVerDefs.put("client_secret", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
      paramVerDefs.put("redirect_uris", ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
      paramVerDefs.put("services",
          new ParameterVerificationDefinition(new ServicesConfigurationValidator(), true));
      paramVerDefs.put("client_prefs",
          new ParameterVerificationDefinition(new ClientPreferencesValidator(), false));
    }


    public SingleOpConfiguration(Map<String, Object> claims) {
      super(claims);
    }

  }

  protected class OpConfigurationValidator implements ClaimValidator<Map<String, Object>> {

    @SuppressWarnings("unchecked")
    @Override
    public Map<String, Object> validate(Object value) throws InvalidClaimException {
      if (!(value instanceof Map)) {
        throw new InvalidClaimException(
            String.format("Parameter '%s' is not of expected type", value));
      }
      Map<String, Object> map = (Map<String, Object>) value;
      SingleOpConfiguration opConfiguration = new SingleOpConfiguration(map);
      if (opConfiguration.verify()) {
        return map;
      }
      throw new InvalidClaimException(
          "Invalid contents in the OP configuration: " + opConfiguration.getError().getDetails());
    }
  }

  protected class ServicesConfiguration extends AbstractMessage {

    public ServicesConfiguration(Map<String, Object> claims) {
      super(claims);
      for (String key : claims.keySet()) {
        paramVerDefs.put(key,
            new ParameterVerificationDefinition(new ServicesConfigurationValidator(), true));
      }
    }

  }

  protected class ServicesConfigurationValidator implements ClaimValidator<List<ServiceConfig>> {

    @SuppressWarnings("unchecked")
    @Override
    public List<ServiceConfig> validate(Object value) throws InvalidClaimException {
      if (value instanceof List) {
        List<?> list = (List<?>) value;
        if (!list.isEmpty() && !(list.get(0) instanceof ServiceConfig)) {
          throw new InvalidClaimException("Invalid contents in the services configuration");
        }
        return (List<ServiceConfig>) value;
      }
      if (value instanceof Map) {
        List<ServiceConfig> serviceConfigs = new ArrayList<>();
        Map<String, Object> servicesMap = (Map<String, Object>) value;
        for (String service : servicesMap.keySet()) {
          Object object = servicesMap.get(service);
          if (object instanceof Map) {
            ServiceConfigMessage serviceConfigMsg = new ServiceConfigMessage(
                (Map<String, Object>) object);
            if (serviceConfigMsg.verify()) {
              try {
                ServiceConfig serviceConfig = ServiceConfig.fromJson(serviceConfigMsg.toJson());
                serviceConfig.setServiceName(getServiceName(service));
                serviceConfigs.add(serviceConfig);
              } catch (DeserializationException | SerializationException e) {
                throw new InvalidClaimException(
                    "Could not construct ServiceConfig from the message contents", e);
              }
            } else {
              throw new InvalidClaimException("Invalid contents in the services configuration: "
                  + serviceConfigMsg.getError().getDetails());
            }
          }
        }
        return serviceConfigs;
      }
      throw new InvalidClaimException("Invalid contents in the services configuration");
    }
  }
  
  protected class ClientPreferencesValidator implements ClaimValidator<RegistrationRequest> {

    @SuppressWarnings("unchecked")
    @Override
    public RegistrationRequest validate(Object value) throws InvalidClaimException {
      if (!(value instanceof Map)) {
        throw new InvalidClaimException(
            String.format("Parameter '%s' is not of expected type", value));
      }
      Map<String, Object> map = (Map<String, Object>) value;
      RegistrationRequest clientPreferences = new RegistrationRequest(map);
      clientPreferences.getParameterVerificationDefinitions().remove("redirect_uris");
      if (clientPreferences.verify()) {
        return clientPreferences;
      }
      throw new InvalidClaimException(
          "Invalid contents in the client preferences: " + clientPreferences.getError().getDetails());
    }
  }


}
