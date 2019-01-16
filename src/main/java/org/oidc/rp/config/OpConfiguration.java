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

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.KeyBundle;
import com.auth0.msg.SYMKey;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

/**
 * This class contains configuration needed for the communication with an OP.
 */
public class OpConfiguration {
  
  /**
   * The issuer name for this OP configuration. Can be null, if only Webfinger is enabled.
   */
  private String issuer;

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
    this(null);
  }
  
  /**
   * Constructor.
   * 
   * @param issuer The issuer name for this OP configuration. Can be null, if only Webfinger is
   *        enabled.
   */
  public OpConfiguration(String issuer) {
    setIssuer(issuer);
    serviceContext = new ServiceContext();
    serviceConfigs = new ArrayList<ServiceConfig>();
  }

  /**
   * Parses a map of OP configurations from the given JSON data.
   * 
   * @param data The JSON as byte array containing one or more OP configurations.
   * @return The map of parsed OP configurations. Keys contain the identifiers and values the
   *         corresponding OP configuration in the JSON the file.
   * @throws DeserializationException If the JSON file cannot be deserialized for any reason.
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
      opConfiguration.setIssuer((String) map.get("issuer"));
      ServiceContext serviceContext = opConfiguration.getServiceContext();
      serviceContext.setBaseUrl(baseUrl);
      serviceContext.setIssuer((String) map.get("issuer"));
      serviceContext.setClientId((String) map.get("client_id"));
      String clientSecret = (String) map.get("client_secret");
      if (!Strings.isNullOrEmpty(clientSecret)) {
        serviceContext.setClientSecret(clientSecret);
        try {
          KeyBundle bundle = new KeyBundle();
          bundle.append(new SYMKey("sig", clientSecret));
          bundle.append(new SYMKey("ver", clientSecret));
          serviceContext.getKeyJar().addKeyBundle("", bundle);
        } catch (ImportException | IOException | JWKException | ValueError e) {
          throw new DeserializationException("Could not add the client secret to the key jar", e);
        }
      }
      List<String> redirectUris = (List<String>) map.get("redirect_uris");
      if (redirectUris != null) {
        for (int i = 0; i < redirectUris.size(); i++) {
          redirectUris.set(i, redirectUris.get(i).replace("${BASEURL}", baseUrl));
        }
      }
      serviceContext.setRedirectUris(redirectUris);
      serviceContext.setClientPreferences((RegistrationRequest) map.get("client_prefs"));
      Map<String, Boolean> allow = (Map<String, Boolean>) map.get("allow");
      if (allow != null && !allow.isEmpty()) {
        serviceContext.setAllow((Map<String, Boolean>) map.get("allow"));
      }
      String jwksUri = (String) map.get("jwks_uri");
      if (!Strings.isNullOrEmpty(jwksUri)) {
        serviceContext.setJwksUri(jwksUri.replace("${BASEURL}", baseUrl));
      }
      opConfiguration.setServiceConfigs((List<ServiceConfig>) map.get("services"));
      for (ServiceConfig serviceConfig : opConfiguration.getServiceConfigs()) {
        if (ServiceName.AUTHORIZATION.equals(serviceConfig.getServiceName())) {
          if (serviceContext.getRedirectUris() == null ||
              serviceContext.getRedirectUris().isEmpty()) {
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
   * @param jsonFile The JSON file containing one or more OP configurations.
   * @return The map of parsed OP configurations. Keys contain the identifiers and values the
   *         corresponding OP configuration in the JSON the file.
   * @throws DeserializationException If the JSON file cannot be deserialized for any reason.
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
  
  /**
   * Get the issuer name for this OP configuration.
   * @return The issuer name for this OP configuration.
   */
  public String getIssuer() {
    return issuer;
  }
  
  /**
   * Sets the issuer name for this OP configuration. Can be null, if only Webfinger is enabled.
   * @param iss What to set.
   */
  public void setIssuer(String iss) {
    issuer = iss;
  }

  /**
   * Get the service context shared between the services related to this OP.
   * @return The service context shared between the services related to this OP.
   */
  public ServiceContext getServiceContext() {
    return serviceContext;
  }
  
  /**
   * Set the service context shared between the services related to this OP.
   * @param context What to set.
   */
  public void setServiceContext(ServiceContext context) {
    serviceContext = context;
  }

  /**
   * Get the list of service configurations for this OP.
   * @return The list of service configurations for this OP.
   */
  public List<ServiceConfig> getServiceConfigs() {
    return serviceConfigs;
  }

  /**
   * Set the list of service configurations for this OP.
   * @param configs What to set.
   */
  public void setServiceConfigs(List<ServiceConfig> configs) {
    serviceConfigs = configs;
  }
  
  /**
   * Get the configuration claims used for initializing service context and service configurations.
   * @return The configuration claims used for initializing service context and service
   *    configurations.
   */
  public Map<String, Object> getConfigurationClaims() {
    return configurationClaims;
  }
  
  /**
   * Set the configuration claims used for initializing service context and service configurations.
   * @param claims What to set.
   */
  public void setConfigurationClaims(Map<String, Object> claims) {
    configurationClaims = claims;
  }
}
