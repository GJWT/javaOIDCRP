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

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HttpContext;
import org.oidc.common.HttpMethod;
import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.ValueException;
import org.oidc.msg.DeserializationException;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Message;
import org.oidc.service.Service;
import org.oidc.service.base.HttpArguments;
import org.oidc.service.base.HttpHeader;

import com.auth0.msg.HttpClientUtil;
import com.auth0.msg.HttpClientUtil.HttpFetchResponse;

/**
 * Utility class for communicating with {@link Service}s via HTTP.
 */
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
      doRequest(httpGet, service, stateKey, httpArguments);
    } else if (HttpMethod.POST.equals(httpArguments.getHttpMethod())) {
      HttpPost httpPost = new HttpPost(httpArguments.getUrl());
      StringEntity entity;
      try {
        entity = new StringEntity(httpArguments.getBody() == null ? "" : httpArguments.getBody());
        httpPost.setEntity(entity);
        doRequest(httpPost, service, stateKey, httpArguments);
      } catch (UnsupportedEncodingException e) {
        throw new ValueException("Could not encode the request", e);
      }
    } else {
      throw new ValueException("Unsupported http method: " + httpArguments.getHttpMethod());
    }
  }
  
  /**
   * Adds headers from the given HTTP arguments to the given HTTP request.
   * 
   * @param request The HTTP request to be populated with headers.
   * @param httpArguments The HTTP arguments where the headers are fetched from.
   */
  protected static void addHeaders(HttpUriRequest request, HttpArguments httpArguments) {
    HttpHeader header = httpArguments.getHeader();
    if (HttpMethod.POST.equals(httpArguments.getHttpMethod()) && header.getContentType() != null) {
      request.setHeader("Content-Type", header.getContentType());
    }
    if (header.getAuthorization() != null) {
      request.setHeader("Authorization", header.getAuthorization());
    }
  }
  
  /**
   * Sends the given request to the remote server, parses the response and updates the service
   * context.
   * 
   * @param request The HTTP request to be sent to the remote server.
   * @param service The service used for parsing the response and updating the service context.
   * @param stateKey The optional state key.
   * @param httpArguments The HTTP request parameters used for the request.
   * @throws MissingRequiredAttributeException If the response is missing a required attribute.
   * @throws ValueException If the response message is unexpected.
   * @throws InvalidClaimException If the response contains invalid claims.
   * @throws IOException If the underlying HTTP client communication fails.
   */
  protected static void doRequest(HttpUriRequest request, Service service, String stateKey, 
      HttpArguments httpArguments)
          throws MissingRequiredAttributeException, ValueException, InvalidClaimException, 
          IOException {
    
    addHeaders(request, httpArguments);
    HttpFetchResponse response = HttpClientUtil.fetchUri(request, (HttpContext) null);

    try {
      Message message = service.parseResponse(response.getBody(), stateKey);
      service.updateServiceContext(message, stateKey);
    } catch (DeserializationException  e) {
      throw new ValueException("The response message could not be deserialized, status code = " +
          response.getStatusCode(), e);
    }
  }

}