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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.apache.http.client.ClientProtocolException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.oidc.common.MessageType;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ServiceName;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.msg.SerializationException;
import org.oidc.msg.oidc.RegistrationResponse;
import org.oidc.rp.config.OpConfiguration;
import org.oidc.rp.oauth2.Client;
import org.oidc.service.base.RequestArgumentProcessingException;
import org.oidc.service.data.State;
import com.auth0.msg.HttpClientUtil;
import junit.framework.Assert;

/**
 * Unit tests for {@link RPHandler}.
 */
public class RPHandlerTest {

  String baseUrl;
  List<OpConfiguration> opConfigurations;
  RPHandler rpHandler;
  
  @Before
  public void setup() throws DeserializationException {
    baseUrl = "https://example.org/";
    String file = "src/test/resources/example_config.json";
    Map<String, OpConfiguration> opConfigs = OpConfiguration.parseFromJson(file, baseUrl);
    opConfigurations = new ArrayList<OpConfiguration>();
    for (OpConfiguration opConfig : opConfigs.values()) {
      opConfigurations.add(opConfig);
    }
    rpHandler = new RPHandler(opConfigurations);
  }
  
  @Test
  public void testConstructors() {
    rpHandler = new RPHandler(opConfigurations);
    Assert.assertEquals(3, rpHandler.getOpConfigurations().size());
    Assert.assertNull(rpHandler.getStateDb().getIssuer("mock"));
    State state = Mockito.mock(State.class);
    String mockedValue = "mockedValue";
    Mockito.when(state.getIssuer(Mockito.anyString())).thenReturn(mockedValue);
    rpHandler = new RPHandler(opConfigurations, state);
    Assert.assertEquals(3, rpHandler.getOpConfigurations().size());
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
    OpConfiguration mockIssuerConfig = 
        rpHandler.getOpConfigurationViaIssuer("https://accounts.example.com/");
    
    Assert.assertNull(rpHandler.getService(mockIssuerConfig, ServiceName.WEBFINGER));
    Assert.assertNull(rpHandler.getService(mockIssuerConfig, ServiceName.REGISTRATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, 
        ServiceName.PROVIDER_INFO_DISCOVERY));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, ServiceName.AUTHORIZATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, ServiceName.ACCESS_TOKEN));
    Assert.assertNotNull(rpHandler.getService(mockIssuerConfig, ServiceName.USER_INFO));

    OpConfiguration mockIssuer2Config = 
        rpHandler.getOpConfigurationViaIssuer("https://accounts.example2.com/");

    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.WEBFINGER));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.REGISTRATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, 
        ServiceName.PROVIDER_INFO_DISCOVERY));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.AUTHORIZATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.ACCESS_TOKEN));
    Assert.assertNull(rpHandler.getService(mockIssuer2Config, ServiceName.USER_INFO));
  }
  
  @Test
  public void testOpConfigurationViaIssuer() {
    String issuer = "https://accounts.example.com/";
    OpConfiguration opConfig = rpHandler.getOpConfigurationViaIssuer(issuer);
    Assert.assertEquals(issuer, opConfig.getIssuer());
    String issuer2 = "https://accounts.example2.com/";
    OpConfiguration opConfig2 = rpHandler.getOpConfigurationViaIssuer(issuer2);
    Assert.assertEquals(issuer2, opConfig2.getIssuer());
    Assert.assertNull(rpHandler.getOpConfigurationViaIssuer("not_existing_issuer"));
    Assert.assertNull(rpHandler.getOpConfigurationViaIssuer(""));
    Assert.assertNull(rpHandler.getOpConfigurationViaIssuer(null));
  }
  
  @Test
  public void testOpDiscoveryNoRegistration() throws MissingRequiredAttributeException, 
      RequestArgumentProcessingException, ValueException, InvalidClaimException, 
      ClientProtocolException, IOException, SerializationException {
    String issuer = "https://accounts.example3.com/";
    HttpClientUtil.setClient(HttpTestingSupport.buildHttpClient(200, 
        HttpTestingSupport.getMinimalOpConfigurationResponse(issuer)));
    BeginResponse beginResponse = rpHandler.begin(issuer, null);
    Client client = rpHandler.getClient(issuer);
    Assert.assertNotNull(client);
    String state = beginResponse.getState();
    Assert.assertNotNull(state);
    String redirectUri = beginResponse.getRedirectUri();
    Assert.assertNotNull(redirectUri);
    Assert.assertTrue(redirectUri.startsWith("https://example.com/authorization"));
    Message storedMsg = rpHandler.getStateDb().getItem(state, MessageType.AUTHORIZATION_REQUEST);
    Assert.assertEquals(redirectUri.substring(redirectUri.indexOf("?") + 1), 
        storedMsg.toUrlEncoded());
    RegistrationResponse behavior = client.getServiceContext().getBehavior();
    Assert.assertNotNull(behavior);
    Map<String, Object> claims = behavior.getClaims();
    Assert.assertTrue(!claims.isEmpty());
    Assert.assertEquals("xxxxxxxxx.apps.exampleusercontent3.com", claims.get("client_id"));
    Assert.assertEquals("3333333333", claims.get("client_secret"));
    Assert.assertEquals(Arrays.asList(baseUrl + "/authz_cb/mockIssuer3"), 
        claims.get("redirect_uris"));
  }
  
}