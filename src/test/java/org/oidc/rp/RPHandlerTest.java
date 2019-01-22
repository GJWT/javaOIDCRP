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
import org.oidc.msg.oauth2.ResponseMessage;
import org.oidc.msg.oidc.AccessTokenResponse;
import org.oidc.msg.oidc.AuthenticationRequest;
import org.oidc.msg.oidc.AuthenticationResponse;
import org.oidc.msg.oidc.IDToken;
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
    Assert.assertEquals(5, rpHandler.getOpConfigurations().size());
    Assert.assertNull(rpHandler.getStateDb().getIssuer("mock"));
    State state = Mockito.mock(State.class);
    String mockedValue = "mockedValue";
    Mockito.when(state.getIssuer(Mockito.anyString())).thenReturn(mockedValue);
    rpHandler = new RPHandler(opConfigurations, state);
    Assert.assertEquals(5, rpHandler.getOpConfigurations().size());
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
  public void testBeginNoAuthorizationService() throws MissingRequiredAttributeException, 
      RequestArgumentProcessingException, ValueException, InvalidClaimException, 
      ClientProtocolException, IOException {
    String issuer = "https://accounts.example5.com/";
    HttpClientUtil.setClient(HttpTestingSupport.buildHttpClient(200, 
        HttpTestingSupport.getMinimalOpConfigurationResponse(issuer, false)));
    BeginResponse beginResponse = rpHandler.begin(issuer, null);
    Assert.assertNotNull(beginResponse);
    Assert.assertNull(beginResponse.getRedirectUri());
    Assert.assertNull(beginResponse.getState());
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
    Assert.assertNull(rpHandler.getService(mockIssuer2Config, ServiceName.REGISTRATION));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, 
        ServiceName.PROVIDER_INFO_DISCOVERY));
    Assert.assertNotNull(rpHandler.getService(mockIssuer2Config, ServiceName.AUTHORIZATION));
    Assert.assertNull(rpHandler.getService(mockIssuer2Config, ServiceName.ACCESS_TOKEN));
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

  @Test(expected = ValueException.class)
  public void testOpDiscoveryFails() throws MissingRequiredAttributeException, 
      RequestArgumentProcessingException, ValueException, InvalidClaimException, 
      ClientProtocolException, IOException, SerializationException {
    String issuer = "https://accounts.example4.com/not_found";
    HttpClientUtil.setClient(HttpTestingSupport.buildHttpClient(200, 
        HttpTestingSupport.getMinimalOpConfigurationResponse(issuer, false)));
    rpHandler.begin(issuer, null);
  }
  
  @Test
  public void testOpDiscoveryNoRegistration() throws MissingRequiredAttributeException, 
      RequestArgumentProcessingException, ValueException, InvalidClaimException, 
      ClientProtocolException, IOException, SerializationException {
    String issuer = "https://accounts.example2.com/";
    BeginResponse beginResponse = setupClient(issuer, null, true);
    String state = beginResponse.getState();
    Assert.assertNotNull(state);
    String redirectUri = beginResponse.getRedirectUri();
    Assert.assertNotNull(redirectUri);
    Assert.assertTrue(redirectUri.startsWith("https://example.com/authorization"));
    Assert.assertTrue(redirectUri.contains("state=" + state));
    Message storedMsg = rpHandler.getStateDb().getItem(state, MessageType.AUTHORIZATION_REQUEST);
    Assert.assertEquals(redirectUri.substring(redirectUri.indexOf("?") + 1), 
        storedMsg.toUrlEncoded());
    Client client = rpHandler.getClient(issuer);
    Assert.assertNotNull(client);
    RegistrationResponse behavior = client.getServiceContext().getBehavior();
    Assert.assertNotNull(behavior);
    Map<String, Object> claims = behavior.getClaims();
    Assert.assertTrue(!claims.isEmpty());
    Assert.assertEquals("xxxxxxxxx.apps.exampleusercontent2.com", claims.get("client_id"));
    Assert.assertEquals("2222222222", claims.get("client_secret"));
    Assert.assertEquals(Arrays.asList(baseUrl + "/authz_cb/mockIssuer2"), 
        claims.get("redirect_uris"));
    
    // rerun also works
    beginResponse = rpHandler.begin(issuer, null);
    Assert.assertNotNull(rpHandler.getClient(issuer));
    Assert.assertNotSame(state, beginResponse.getState());
  }
  
  protected BeginResponse setupClient(String issuer, String userId, boolean code)
      throws ClientProtocolException, IOException, MissingRequiredAttributeException, 
      RequestArgumentProcessingException, ValueException, InvalidClaimException {
    HttpClientUtil.setClient(HttpTestingSupport.buildHttpClient(200, 
        HttpTestingSupport.getMinimalOpConfigurationResponse(issuer, code)));
    return rpHandler.begin(issuer, userId);
  }

  @Test(expected = ValueException.class)
  public void testWebfingerIssuerNotFound() throws ClientProtocolException, IOException, 
      MissingRequiredAttributeException, RequestArgumentProcessingException, ValueException, 
      InvalidClaimException {
    String issuer = "https://accounts.example2.com/";
    String userId = "john.doe@example.org";
    HttpClientUtil.setClient(HttpTestingSupport.buildHttpClient(200, 
        HttpTestingSupport.getMinimalWebfingerResponse(userId, issuer + "invalid/")));
    rpHandler.begin(null, userId);
  }

  @Test
  public void testWebfingerSuccess() throws ClientProtocolException, IOException, 
      MissingRequiredAttributeException, RequestArgumentProcessingException, ValueException, 
      InvalidClaimException {
    String issuer = "https://accounts.example2.com/";
    String userId = "john.doe@example.org";
    HttpClientUtil.setClient(HttpTestingSupport.buildHttpClient(200, 
        HttpTestingSupport.getMinimalWebfingerResponse(userId, issuer)));
    Assert.assertEquals(issuer, rpHandler.callWebfingerServices(userId).getIssuer());
  }

  @Test(expected = ValueException.class)
  public void testAccessTokenResponseNoService() throws ClientProtocolException, IOException, 
      MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {
    String accessToken = "mockAccessToken";
    String refreshToken = "mockRefreshToken";
    String issuer = "https://accounts.example2.com/";
    getAccessTokenResponse(accessToken, refreshToken, issuer);
  }
  
  protected Message getAccessTokenResponse(String accessToken, String refreshToken, String issuer)
      throws ClientProtocolException, IOException, MissingRequiredAttributeException, 
      RequestArgumentProcessingException, ValueException, InvalidClaimException {
    BeginResponse beginResponse = setupClient(issuer, null, true);
    HttpClientUtil.setClient(HttpTestingSupport.buildHttpClient(200, 
        HttpTestingSupport.getAccessTokenResponse(accessToken, refreshToken)));
    return rpHandler.getAccessTokenResponse(beginResponse.getState(), 
        rpHandler.getClient(issuer));
    
  }

  @Test
  public void testAccessTokenResponse() throws ClientProtocolException, IOException, 
      MissingRequiredAttributeException, ValueException, InvalidClaimException, 
      RequestArgumentProcessingException {
    String accessToken = "mockAccessToken";
    String refreshToken = "mockRefreshToken";
    String issuer = "https://accounts.example4.com/";
    Message message = getAccessTokenResponse(accessToken, refreshToken, issuer);
    Assert.assertTrue(message instanceof AccessTokenResponse);
    AccessTokenResponse response = (AccessTokenResponse) message;
    Assert.assertEquals(accessToken, response.getClaims().get("access_token"));    
    Assert.assertEquals(refreshToken, response.getClaims().get("refresh_token"));
  }

  @Test(expected = ValueException.class)
  public void testResolveTokensNoRequest() throws MissingRequiredAttributeException, 
      ValueException, InvalidClaimException, RequestArgumentProcessingException {
    rpHandler.resolveTokens(null, "not existing", null);
  }

  @Test
  public void testResolveTokensError() throws MissingRequiredAttributeException, ValueException, 
      InvalidClaimException, RequestArgumentProcessingException, ClientProtocolException, 
      IOException {
    String issuer = "https://accounts.example4.com/";
    String state = "mockState";
    
    RPHandler mockHandler = Mockito.spy(rpHandler);
    AuthenticationRequest authenticationRequest = new AuthenticationRequest();
    authenticationRequest.getClaims().put("response_type", "code");
    mockHandler.getStateDb().createStateRecord(issuer, state);
    mockHandler.getStateDb().storeItem(authenticationRequest, state, 
        MessageType.AUTHORIZATION_REQUEST);
    AuthenticationResponse authenticationResponse = Mockito.mock(AuthenticationResponse.class);
    Mockito.when(authenticationResponse.getVerifiedIdToken()).thenReturn(null);
    String errorCode = "mockError";
    String errorDescription = "mockErrorDescription";
    String errorUri = "mockErrorUri";
    Message message = createErrorResponse(errorCode, errorDescription, errorUri);
    Mockito.doReturn(message).when(mockHandler).getAccessTokenResponse((String) Mockito.any(), 
        (Client) Mockito.any());
    ResolveTokensResponse response = mockHandler.resolveTokens(authenticationResponse, state, 
        mockHandler.getClient(issuer));
    Assert.assertEquals(errorCode, response.getErrorCode());
    Assert.assertEquals(errorDescription, response.getErrorDescription());
    Assert.assertEquals(errorUri, response.getErrorUri());
  }
  
  protected ResponseMessage createErrorResponse(String errorCode, String errorDescription, 
      String errorUri) {
    ResponseMessage message = new ResponseMessage();
    message.addClaim("error", errorCode);
    message.addClaim("error_description", errorDescription);
    message.addClaim("error_uri", errorUri);
    return message;
  }

  @Test
  public void testResolveTokens() throws MissingRequiredAttributeException, ValueException, 
      InvalidClaimException, RequestArgumentProcessingException, ClientProtocolException, 
      IOException {
    String issuer = "https://accounts.example4.com/";
    String state = "mockState";
    
    RPHandler mockHandler = Mockito.spy(rpHandler);
    AuthenticationRequest authenticationRequest = new AuthenticationRequest();
    authenticationRequest.getClaims().put("response_type", "id_token token code");
    mockHandler.getStateDb().createStateRecord(issuer, state);
    mockHandler.getStateDb().storeItem(authenticationRequest, state, 
        MessageType.AUTHORIZATION_REQUEST);
    AuthenticationResponse authenticationResponse = Mockito.mock(AuthenticationResponse.class);
    IDToken idToken = Mockito.mock(IDToken.class);
    Mockito.when(idToken.getIssuer()).thenReturn(issuer);
    Mockito.when(authenticationResponse.getVerifiedIdToken()).thenReturn(idToken);
    AccessTokenResponse message = Mockito.spy(new AccessTokenResponse());
    Mockito.doReturn(idToken).when(message).getVerifiedIdToken();
    String accessToken = "mockAccessToken";
    String refreshToken = "mockRefreshToken";
    message.addClaim("access_token", accessToken);
    message.addClaim("refresh_token", refreshToken);
    Mockito.when(message.getVerifiedIdToken()).thenReturn(idToken);
    Mockito.doReturn(message).when(mockHandler).getAccessTokenResponse((String) Mockito.any(), 
        (Client) Mockito.any());
    ResolveTokensResponse response = mockHandler.resolveTokens(authenticationResponse, state, 
        mockHandler.getClient(issuer));
    Assert.assertEquals(issuer, response.getIDToken().getIssuer());
    Assert.assertEquals(accessToken, response.getAccessToken());
    Assert.assertEquals(refreshToken, response.getRefreshToken());
  }
  
  @Test(expected = DeserializationException.class)
  public void testFinalizeAuthenticationInvalidMessage() throws DeserializationException,
      ValueException, InvalidClaimException, MissingRequiredAttributeException, 
      ClientProtocolException, IOException, RequestArgumentProcessingException {
    String issuer = "https://accounts.example4.com/";
    setupClient(issuer, null, true);
    rpHandler.finalizeAuthentication(rpHandler.getClient(issuer), issuer, "foo=bar");
  }
  
  @Test
  public void testFinalizeAuthenticationErrorResponse() throws DeserializationException,
      ValueException, InvalidClaimException, MissingRequiredAttributeException, 
      ClientProtocolException, IOException, RequestArgumentProcessingException,
      SerializationException {
    String issuer = "https://accounts.example4.com/";
    setupClient(issuer, null, true);
    String errorCode = "mockError";
    String errorDescription = "mockErrorDescription";
    String errorUri = "mockErrorUri";
    Message message = createErrorResponse(errorCode, errorDescription, errorUri);
    ResponseMessage response = rpHandler.finalizeAuthentication(rpHandler.getClient(issuer), 
        issuer, "https://example.com?" + message.toUrlEncoded());
    Assert.assertEquals(errorCode, response.getClaims().get("error"));
    Assert.assertEquals(errorDescription, response.getClaims().get("error_description"));
    Assert.assertEquals(errorUri, response.getClaims().get("error_uri"));    
  }
  
  @Test(expected = ValueException.class)
  public void testFinalizeAuthenticationNoStoredIssuer() throws DeserializationException,
      ValueException, InvalidClaimException, MissingRequiredAttributeException, 
      ClientProtocolException, IOException, RequestArgumentProcessingException {
    String issuer = "https://accounts.example4.com/";
    setupClient(issuer, null, true);
    rpHandler.finalizeAuthentication(rpHandler.getClient(issuer), issuer,
        "https://example.com/?state=bar");
  }

  @Test(expected = ValueException.class)
  public void testFinalizeAuthenticationIssuerMismatch() throws DeserializationException,
      ValueException, InvalidClaimException, MissingRequiredAttributeException, 
      ClientProtocolException, IOException, RequestArgumentProcessingException {
    String issuer = "https://accounts.example4.com/";
    setupClient(issuer, null, true);
    String state = "mockState";
    rpHandler.getStateDb().createStateRecord(issuer + "2", state);
    rpHandler.finalizeAuthentication(rpHandler.getClient(issuer), issuer,
        "https://example.com/?state=" + state);
  }

  @Test
  public void testFinalizeAuthenticationSuccess() throws DeserializationException, ValueException,
      InvalidClaimException, MissingRequiredAttributeException, ClientProtocolException,
      IOException, RequestArgumentProcessingException {
    String issuer = "https://accounts.example4.com/";
    setupClient(issuer, null, true);
    String state = "mockState";
    rpHandler.getStateDb().createStateRecord(issuer, state);
    ResponseMessage response = rpHandler.finalizeAuthentication(rpHandler.getClient(issuer),
        issuer, "https://example.com/?state=" + state);
    Assert.assertTrue(response instanceof AuthenticationResponse);
    Assert.assertEquals(state, response.getClaims().get("state"));
  }
  
  @Test(expected = MissingRequiredAttributeException.class)
  public void testFinalizeNoClient() throws MissingRequiredAttributeException,
      DeserializationException, ValueException, InvalidClaimException,
      RequestArgumentProcessingException {
    rpHandler.finalize("not_existing_issuer", null);
  }

  @Test
  public void testFinalizeErrorResponse() throws MissingRequiredAttributeException,
      DeserializationException, ValueException, InvalidClaimException,
      RequestArgumentProcessingException, ClientProtocolException, IOException,
      SerializationException {
    String issuer = "https://accounts.example4.com/";
    setupClient(issuer, null, true);
    String errorCode = "mockError";
    String errorDescription = "mockErrorDescription";
    String errorUri = "mockErrorUri";
    Message message = createErrorResponse(errorCode, errorDescription, errorUri);
    FinalizeResponse response = rpHandler.finalize(issuer, "https://example.com?" + 
        message.toUrlEncoded());
    Assert.assertEquals(errorCode, response.getErrorCode());
    Assert.assertEquals(errorDescription, response.getErrorDescription());
    Assert.assertEquals(errorUri, response.getErrorUri());    
  }

  @Test
  public void testFinalizeErrorFromResolveTokens() throws MissingRequiredAttributeException,
      DeserializationException, ValueException, InvalidClaimException,
      RequestArgumentProcessingException, ClientProtocolException, IOException,
      SerializationException {
    String issuer = "https://accounts.example4.com/";
    setupClient(issuer, null, true);
    String state = "mockState";
    RPHandler mockHandler = Mockito.spy(rpHandler);
    mockHandler.getStateDb().createStateRecord(issuer, state);
    IDToken idToken = new IDToken();
    String claim = "mockClaim";
    String value = "mockValue";
    idToken.addClaim(claim, value);
    String accessToken = "mockAccessToken";
    String refreshToken = "mockRefreshToken";
    ResolveTokensResponse tokensResponse = new ResolveTokensResponse(idToken, accessToken, 
        refreshToken);
    Mockito.doReturn(tokensResponse).when(mockHandler).resolveTokens((AuthenticationResponse) 
        Mockito.any(), Mockito.anyString(), (Client) Mockito.any());
    FinalizeResponse response = mockHandler.finalize(issuer, "https://example.com?state=" + state);
    Assert.assertEquals(accessToken, response.getAccessToken());
    Assert.assertEquals(refreshToken, response.getRefreshToken());
    Assert.assertEquals(value, response.getUserClaims().getClaims().get(claim));
  }

}