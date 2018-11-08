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

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.service.Service;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.HttpHeader;

public class HttpClientWrapper {
  
  /**
   * Sends the given request to the remote server, parses the response and updates the service
   * context.
   * 
   * @param httpArguments The HTTP request parameters used for constructing the HTTP request.
   * @param service The service used for parsing the response and updating the service context.
   * @param stateKey The optional state key.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the response message is unexpected.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws IOException If the underlying HTTP client communication fails.
   */
  public static void doRequest(HttpArguments httpArguments, Service service, String stateKey) 
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, IOException {
    if (HttpMethod.GET.equals(httpArguments.getHttpMethod())) {
      HttpGet httpGet = new HttpGet(httpArguments.getUrl());
      doRequest(httpGet, service, stateKey);
    } else if (HttpMethod.POST.equals(httpArguments.getHttpMethod())) {
      HttpPost httpPost = new HttpPost(httpArguments.getUrl());
      HttpHeader header = httpArguments.getHeader();
      if (header.getContentType() != null) {
        httpPost.setHeader("Content-Type", header.getContentType());
      }
      if (header.getAuthorization() != null) {
        httpPost.setHeader("Authorization", header.getAuthorization());
      }
      StringEntity entity;
      try {
        entity = new StringEntity(httpArguments.getBody());
        System.out.println("Sending payload: " + httpArguments.getBody());
        httpPost.setEntity(entity);
        doRequest(httpPost, service, stateKey);
      } catch (UnsupportedEncodingException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
    }
  }
  
  /**
   * Sends the given request to the remote server, parses the response and updates the service
   * context.
   * 
   * @param request The HTTP request to be sent to the remote server.
   * @param service The service used for parsing the response and updating the service context.
   * @param stateKey The optional state key.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the response message is unexpected.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws IOException If the underlying HTTP client communication fails.
   */
  protected static void doRequest(HttpUriRequest request, Service service, String stateKey)
      throws MissingRequiredAttributeException, ValueException, InvalidClaimException, IOException {
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      try (CloseableHttpResponse response = httpClient.execute(request)) {
        System.out.println(response.getStatusLine());
        HttpEntity entity = response.getEntity();
        try {
          Message message = service.parseResponse(EntityUtils.toString(entity), stateKey);
          service.updateServiceContext(message, stateKey);
          System.out.println(service.getServiceContext().getIssuer());
        } catch (DeserializationException  e) {
          throw new ValueException("The response message could not be deserialized", e);
        } finally {
          EntityUtils.consume(entity);
        }
      } 
    } 
  }

}