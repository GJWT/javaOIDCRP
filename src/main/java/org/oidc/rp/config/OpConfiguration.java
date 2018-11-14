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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oidc.common.ServiceName;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.oidc.RegistrationRequest;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * This class contains configuration needed for the communication with an OP.
 */
public class OpConfiguration {

  /**
   * All information that a client needs to talk to an OP server. This is shared by various
   * services.
   */
  private ServiceContext serviceContext;

  /**
   * The configurations for the list of services related to this OP configuration.
   */
  private List<ServiceConfig> serviceConfigs;
  
  /**
   * The configuration claims used for initializing service context and service configurations.
   */
  private Map<String, Object> configurationClaims;

  /**
   * Constructor.
   */
  public OpConfiguration() {
    serviceContext = new ServiceContext();
    serviceConfigs = new ArrayList<ServiceConfig>();
  }

  /**
   * Parses a map of OP configurations from the given JSON data.
   * 
   * @param data
   *          The JSON as byte array containing one or more OP configurations.
   * @return The map of parsed OP configurations. Keys contain the identifiers and values the
   *         corresponding OP configuration in the JSON the file.
   * @throws DeserializationException
   *           If the JSON file cannot be deserialized for any reason.
   */
  @SuppressWarnings("unchecked")
  public static Map<String, OpConfiguration> parseFromJson(byte[] data, String baseUrl)
      throws DeserializationException {
    Map<String, Object> configs;
    try {
      ObjectMapper objectMapper = new ObjectMapper();
      configs = objectMapper.readValue(data, new TypeReference<HashMap<String, Object>>() {
      });
    } catch (IOException e) {
      throw new DeserializationException("Could not deserialize the JSON file from " 
          +  new String(data), e);
    }
    OpConfigurationsMessage configsMsg = new OpConfigurationsMessage(configs);
    if (!configsMsg.verify()) {
      throw new DeserializationException(configsMsg.getError().getDetails().toString());
    }
    Map<String, OpConfiguration> result = new HashMap<>();
    for (String key : configs.keySet()) {
      Map<String, Object> map = (Map<String, Object>) configs.get(key);
      OpConfiguration opConfiguration = new OpConfiguration();
      opConfiguration.getServiceContext().setIssuer((String) map.get("issuer"));
      opConfiguration.getServiceContext().setClientId((String) map.get("client_id"));
      opConfiguration.getServiceContext().setClientSecret((String) map.get("client_secret"));
      List<String> redirectUris = (List<String>) map.get("redirect_uris");
      if (redirectUris != null) {
        for (int i = 0; i < redirectUris.size(); i++) {
          redirectUris.set(i, redirectUris.get(i).replace("${BASEURL}", baseUrl));
        }
      }
      opConfiguration.getServiceContext().setRedirectUris(redirectUris);
      opConfiguration.getServiceContext().setClientPreferences((RegistrationRequest) 
          map.get("client_prefs"));
      opConfiguration.setServiceConfigs((List<ServiceConfig>) map.get("services"));
      for (ServiceConfig serviceConfig : opConfiguration.getServiceConfigs()) {
        if (ServiceName.AUTHORIZATION.equals(serviceConfig.getServiceName())) {
          if (opConfiguration.getServiceContext().getRedirectUris() == null || 
              opConfiguration.getServiceContext().getRedirectUris().isEmpty()) {
            throw new DeserializationException(
                "'redirect_uris' must not be null if authorization service exists");
          }
        }
      }
      opConfiguration.setConfigurationClaims(map);
      result.put(key, opConfiguration);
    }
    return result;    
  }
  
  /**
   * Parses a map of OP configurations from the given JSON file.
   * 
   * @param jsonFile
   *          The JSON file containing one or more OP configurations.
   * @return The map of parsed OP configurations. Keys contain the identifiers and values the
   *         corresponding OP configuration in the JSON the file.
   * @throws DeserializationException
   *           If the JSON file cannot be deserialized for any reason.
   */
  public static Map<String, OpConfiguration> parseFromJson(String jsonFile, String baseUrl)
      throws DeserializationException {
    try {
      byte[] data = Files.readAllBytes(Paths.get(jsonFile));
      return parseFromJson(data, baseUrl);
    } catch (IOException e) {
      throw new DeserializationException("Could not read the data from JSON file " + jsonFile, e);
    }
  }

  public ServiceContext getServiceContext() {
    return serviceContext;
  }
  
  public void setServiceContext(ServiceContext context) {
    serviceContext = context;
  }

  public List<ServiceConfig> getServiceConfigs() {
    return serviceConfigs;
  }

  public void setServiceConfigs(List<ServiceConfig> configs) {
    serviceConfigs = configs;
  }
  
  public Map<String, Object> getConfigurationClaims() {
    return configurationClaims;
  }
  
  public void setConfigurationClaims(Map<String, Object> claims) {
    configurationClaims = claims;
  }
}
