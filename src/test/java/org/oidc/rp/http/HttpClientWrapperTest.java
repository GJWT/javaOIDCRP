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

package org.oidc.rp.http;

import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.protocol.HttpContext;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.oidc.common.HttpMethod;
import org.oidc.common.ValueException;
import org.oidc.service.Service;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.HttpHeader;
import org.oidc.service.base.ServiceContext;
import org.oidc.service.oidc.ProviderInfoDiscovery;

import com.auth0.msg.HttpClientUtil;

import junit.framework.Assert;

/**
 * Unit tests for {@link HttpClientWrapper}.
 */
public class HttpClientWrapperTest {
  
  String url;
  String authorization;
  String contentType;
  
  @Before
  public void init() {
    url = "https://mock.example.org/";
    authorization = "mockAuthorization";
    contentType = "application/mock";
  }
  
  @Test
  public void testGetAddHeaders() {
    testAddHeaders(new HttpGet(url), HttpMethod.GET);
  }

  @Test
  public void testPostAddHeaders() {
    testAddHeaders(new HttpPost(url), HttpMethod.POST);
  }
  
  protected void testAddHeaders(HttpUriRequest request, HttpMethod method) {
    HttpHeader header = new HttpHeader();
    header.setAuthorization(authorization);
    header.setContentType(contentType);
    HttpArguments httpArguments = new HttpArguments(method, url, null, header);
    Assert.assertEquals(0, request.getHeaders("Authorization").length);
    Assert.assertEquals(0, request.getHeaders("Content-Type").length);
    HttpClientWrapper.addHeaders(request, httpArguments);
    Assert.assertEquals(1, request.getHeaders("Authorization").length);
    if (HttpMethod.POST.equals(method)) {
      Assert.assertEquals(1, request.getHeaders("Content-Type").length);      
    } else {
      Assert.assertEquals(0, request.getHeaders("Content-Type").length);
    }
  }

  @Test(expected = ValueException.class)
  public void testGetUnparseableResponse() throws Exception {
    HttpClientUtil.setClient(buildHttpClient(200, "mock"));
    Service service = new ProviderInfoDiscovery(buildServiceContext(), null, null);
    HttpClientWrapper.doRequest(new HttpArguments(HttpMethod.GET, url), service, null);
  }

  @Test(expected = ValueException.class)
  public void testPostUnparseableResponseNullRequest() throws Exception {
    HttpClientUtil.setClient(buildHttpClient(200, "mock"));
    Service service = new ProviderInfoDiscovery(buildServiceContext(), null, null);
    HttpClientWrapper.doRequest(new HttpArguments(HttpMethod.POST, url), service, null);
  }

  @Test(expected = ValueException.class)
  public void testPostUnparseableResponseMockRequest() throws Exception {
    HttpClientUtil.setClient(buildHttpClient(200, "mock"));
    Service service = new ProviderInfoDiscovery(buildServiceContext(), null, null);
    HttpClientWrapper.doRequest(new HttpArguments(HttpMethod.POST, url, "mockRequest", null), 
        service, null);
  }

  @Test
  public void testGetParseableResponse() throws Exception {
    HttpClientUtil.setClient(buildHttpClient(200, getMinimalOpConfigurationResponse()));
    Service service = new ProviderInfoDiscovery(buildServiceContext(), null, null);
    HttpClientWrapper.doRequest(new HttpArguments(HttpMethod.GET, url), service, null);
  }
  
  @Test(expected = ValueException.class)
  public void testInvalidMethod() throws Exception {
    HttpClientWrapper.doRequest(new HttpArguments(null), null, null);
  }

  protected CloseableHttpClient buildHttpClient(int statusCode, String body) throws Exception {
    CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
    CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
    StatusLine statusLine = Mockito.mock(StatusLine.class);
    Mockito.when(statusLine.getStatusCode()).thenReturn(statusCode);
    Mockito.when(httpResponse.getStatusLine()).thenReturn(statusLine);
    StringEntity entity = new StringEntity(body);
    Mockito.when(httpResponse.getEntity()).thenReturn(entity);
    Mockito.when(httpClient.execute((HttpUriRequest) Mockito.any(), 
        (HttpContext) Mockito.any())).thenReturn(httpResponse);
    return httpClient;
  }
  
  protected ServiceContext buildServiceContext() {
    ServiceContext serviceContext = new ServiceContext();
    serviceContext.setIssuer("https://www.example.com");
    return serviceContext;
  }

  protected String getMinimalOpConfigurationResponse() {
    return "{\n" + "\"response_types_supported\": [\"id_token\"],\n"
        + "\"subject_types_supported\": [\"public\", \"pairwise\"],\n"
        + "\"id_token_signing_alg_values_supported\": [\n"
        + "    \"RS256\", \"RS384\", \"RS512\",\n" + "    \"ES256\", \"ES384\", \"ES512\",\n"
        + "    \"HS256\", \"HS384\", \"HS512\",\n"
        + "    \"PS256\", \"PS384\", \"PS512\", \"none\"],\n"
        + "\"issuer\": \"https://www.example.com\",\n"
        + "\"jwks_uri\": \"https://example.com/static/jwks_tE2iLbOAqXhe8bqh.json\",\n"
        + "\"authorization_endpoint\": \"https://example.com/authorization\"}";
  }
}
