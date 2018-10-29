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

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.oidc.common.ServiceName;
import org.oidc.msg.DeserializationException;
import org.oidc.service.base.ServiceConfig;
import org.oidc.service.base.ServiceContext;

import junit.framework.Assert;

/**
 * Unit tests for {@link OpConfiguration}.
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
  public void test() throws DeserializationException {
    Map<String, OpConfiguration> opConfigs = OpConfiguration.parseFromJson(file, baseUrl);
    Assert.assertNotNull(opConfigs);
    Assert.assertEquals(1, opConfigs.size());
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

}
