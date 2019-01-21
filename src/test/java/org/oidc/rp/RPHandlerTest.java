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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.msg.DeserializationException;
import org.oidc.rp.config.OpConfiguration;
import org.oidc.service.data.State;

import junit.framework.Assert;

/**
 * Unit tests for {@link RPHandler}.
 */
public class RPHandlerTest {

  String baseUrl;
  List<OpConfiguration> opConfigurations;
  RPHandler rpHandler;
  
  OpConfiguration mockIssuerConfig;
  OpConfiguration mockIssuer2Config;
  
  @Before
  public void setup() throws DeserializationException {
    baseUrl = "https://example.org/";
    String file = "src/test/resources/example_config.json";
    Map<String, OpConfiguration> opConfigs = OpConfiguration.parseFromJson(file, baseUrl);
    opConfigurations = new ArrayList<OpConfiguration>();
    for (OpConfiguration opConfig : opConfigs.values()) {
      opConfigurations.add(opConfig);
    }
    mockIssuerConfig = opConfigs.get("mockIssuer");
    mockIssuer2Config = opConfigs.get("mockIssuer2");
    rpHandler = new RPHandler(opConfigurations);
  }
  
  @Test
  public void testConstructors() {
    rpHandler = new RPHandler(opConfigurations);
    Assert.assertEquals(2, rpHandler.getOpConfigurations().size());
    Assert.assertNull(rpHandler.getStateDb().getIssuer("mock"));
    State state = Mockito.mock(State.class);
    String mockedValue = "mockedValue";
    Mockito.when(state.getIssuer(Mockito.anyString())).thenReturn(mockedValue);
    rpHandler = new RPHandler(opConfigurations, state);
    Assert.assertEquals(2, rpHandler.getOpConfigurations().size());
    Assert.assertEquals(mockedValue, rpHandler.getStateDb().getIssuer("mock"));
    
    rpHandler = new RPHandler(opConfigurations.get(0));
    Assert.assertEquals(1, rpHandler.getOpConfigurations().size());
    Assert.assertNull(rpHandler.getStateDb().getIssuer("mock"));
    rpHandler = new RPHandler(opConfigurations.get(0), state);
    Assert.assertEquals(1, rpHandler.getOpConfigurations().size());
    Assert.assertEquals(mockedValue, rpHandler.getStateDb().getIssuer("mock"));
  }
  
  @Test(expected = MissingRequiredAttributeException.class)
  public void testBeginNoIssuerNorUserId() throws Exception {
    rpHandler.begin(null, null);
  }
  
  @Test
  public void testGetService() {
    Assert.assertNull(rpHandler.getService(mockIssuerConfig, ServiceName.WEBFINGER));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, ServiceName.REGISTRATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, ServiceName.PROVIDER_INFO_DISCOVERY));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, ServiceName.AUTHORIZATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, ServiceName.ACCESS_TOKEN));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, ServiceName.USER_INFO));

    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.WEBFINGER));
    Assert.assertNull(rpHandler.getService(mockIssuer2Config, ServiceName.REGISTRATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.PROVIDER_INFO_DISCOVERY));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.AUTHORIZATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.ACCESS_TOKEN));
    Assert.assertNull(rpHandler.getService(mockIssuer2Config, ServiceName.USER_INFO));
  }
  
  @Test
  public void testOpConfigurationViaIssuer() {
   
  }
  
}