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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.oidc.common.ServiceName;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.rp.config.OpConfigurationsMessage.OpConfigurationValidator;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;

import junit.framework.Assert;

/**
 * Unit tests for {@link OpConfiguration} and {@link OpConfigurationsMessage}.
 */
public class OpConfigurationTest {
  
  String file;
  
  String issuer;
  String baseUrl;
  String clientId;
  String clientSecret;
  String redirectUri;
  List<String> responseTypes;
  List<String> scope;
 
  @Before
  public void setup() {
    file = "src/test/resources/example_config.json";
    issuer = "https://accounts.example.com/";
    baseUrl = "https://mock.example.org/rp";
    clientId = "xxxxxxxxx.apps.exampleusercontent.com";
    clientSecret = "2222222222";
    redirectUri = baseUrl + "/authz_cb/mockIssuer";
    responseTypes = Arrays.asList("code");
    scope = Arrays.asList("openid", "profile", "email");
  }
  
  @Test
  public void testWithFile() throws DeserializationException {
    Map<String, OpConfiguration> opConfigs = OpConfiguration.parseFromJson(file, baseUrl);
    Assert.assertNotNull(opConfigs);
    Assert.assertEquals(2, opConfigs.size());
    OpConfiguration opConfig = opConfigs.get("mockIssuer");
    Assert.assertNotNull(opConfig);
    ServiceConfig registrationConfig = null;
    for (ServiceConfig config : opConfig.getServiceConfigs()) {
      if (ServiceName.REGISTRATION.equals(config.getServiceName())) {
        registrationConfig = config;
      }
    }
    Assert.assertNotNull(registrationConfig);
    ServiceContext serviceContext = opConfig.getServiceContext();
    Assert.assertEquals(issuer, serviceContext.getIssuer());
    Assert.assertEquals(clientId, serviceContext.getClientId());
    Assert.assertEquals(clientSecret, serviceContext.getClientSecret());
    Assert.assertEquals(Arrays.asList(redirectUri), serviceContext.getRedirectUris());
    Map<String, Object> clientPrefs = serviceContext.getClientPreferences().getClaims();
    Assert.assertEquals(responseTypes, clientPrefs.get("response_types"));
    Assert.assertEquals(scope, clientPrefs.get("scope"));
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorNotMap() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    validator.validate("not a map");
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorIssuerNotString() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    map.put("issuer", Arrays.asList("not a raw string"));
    validator.validate(map);
  }

  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorServicesRawString() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    map.put("services", "not a list or map");
    validator.validate(map);
  }

  @Test
  public void testOpConfigurationValidatorServicesEmptyList() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    map.put("services", new ArrayList<String>());
    Map<String, Object> claims =  validator.validate(map);
    Object services = claims.get("services");
    Assert.assertTrue(services instanceof List);
    Assert.assertEquals(0, ((List<?>) services).size());
  }

  @Test
  public void testOpConfigurationValidatorServicesCorrectList() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    ServiceConfig config = new ServiceConfig();
    map.put("services", Arrays.asList(config));
    Map<String, Object> claims =  validator.validate(map);
    Object services = claims.get("services");
    Assert.assertTrue(services instanceof List);
    List<?> list = (List<?>) services;
    Assert.assertEquals(1, list.size());
    Assert.assertTrue(list.get(0) instanceof ServiceConfig);
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorServicesInvalidServices() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    Map<String, Object> valueMap = new HashMap<>();
    valueMap.put("mockKey", "mockValue");
    map.put("services", valueMap);
    validator.validate(map);
  }

  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorServicesInvalidMap() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    Map<String, Object> valueMap = new HashMap<>();
    Map<String, Object> inter = new HashMap<>();
    valueMap.put("default_authn_method", Arrays.asList("not a raw string"));
    inter.put("MockService", valueMap);
    map.put("services", inter);
    validator.validate(map);
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorServicesWrongList() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    map.put("services", Arrays.asList("not service config"));
    validator.validate(map);
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorPreferencesNotMap() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    map.put("client_prefs", Arrays.asList("not a map"));
    map.put("services", new ArrayList<String>());
    validator.validate(map);
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorPreferencesInvalidMap() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    Map<String, Object> valueMap = new HashMap<>();
    valueMap.put("jwks", "not a map");
    map.put("client_prefs", valueMap);
    map.put("services", new ArrayList<String>());
    validator.validate(map);
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorAllowNotMap() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    map.put("allow", Arrays.asList("not a map"));
    map.put("services", new ArrayList<String>());
    validator.validate(map);
  }
  
  @Test(expected = InvalidClaimException.class)
  public void testOpConfigurationValidatorAllowInvalidMap() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    Map<String, Object> valueMap = new HashMap<>();
    valueMap.put("mockAllow", Arrays.asList("not a boolean or string"));
    map.put("allow", valueMap);
    map.put("services", new ArrayList<String>());
    validator.validate(map);
  }
  
  @Test
  public void testOpConfigurationValidatorAllowValidStringdMap() throws InvalidClaimException {
    OpConfigurationValidator validator = initializeOpConfigurationValidator();
    Map<String, Object> map = new HashMap<>();
    Map<String, Object> valueMap = new HashMap<>();
    valueMap.put("mockAllow", "parsed to false");
    map.put("allow", valueMap);
    map.put("services", new ArrayList<String>());
    Map<String, Object> claims = validator.validate(map);
    Object allow = claims.get("allow");
    Assert.assertTrue(allow instanceof Map);
    Map<?, ?> allowMap = (Map<?, ?>) allow;
    Assert.assertEquals(1, allowMap.keySet().size());
    Assert.assertTrue(allowMap.get("mockAllow") instanceof Boolean);
    Assert.assertFalse((Boolean) allowMap.get("mockAllow"));
  }

  protected OpConfigurationValidator initializeOpConfigurationValidator() {
    OpConfigurationsMessage message = new OpConfigurationsMessage(new HashMap<String, Object>());
    return message.new OpConfigurationValidator();
  }
  
}
