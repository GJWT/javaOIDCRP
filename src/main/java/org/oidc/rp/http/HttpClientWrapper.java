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

public class HttpClientWrapper {
  
  public static void doRequest(HttpArguments httpArguments, Service service) {
    if (HttpMethod.GET.equals(httpArguments.getHttpMethod())) {
      HttpGet httpGet = new HttpGet(httpArguments.getUrl());
      doRequest(httpGet, service);
    } else if (HttpMethod.POST.equals(httpArguments.getHttpMethod())) {
      HttpPost httpPost = new HttpPost(httpArguments.getUrl());
      httpPost.setHeader("Content-Type", "application/json");
      StringEntity entity;
      try {
        entity = new StringEntity(httpArguments.getBody());
        System.out.println("Sending payload: " + httpArguments.getBody());
        httpPost.setEntity(entity);
        doRequest(httpPost, service);
      } catch (UnsupportedEncodingException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
    }
  }
  
  protected static void doRequest(HttpUriRequest request, Service service) {
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      try (CloseableHttpResponse response = httpClient.execute(request)) {
        System.out.println(response.getStatusLine());
        HttpEntity entity = response.getEntity();
        try {
          Message message = service.parseResponse(EntityUtils.toString(entity));
          service.updateServiceContext(message);
          System.out.println(service.getServiceContext().getIssuer());
        } catch (DeserializationException | MissingRequiredAttributeException | ValueException | InvalidClaimException e) {
          //TODO: inform caller
          e.printStackTrace();
        } finally {
          EntityUtils.consume(entity);
        }
      } 
    } catch (IOException e) {
      //TODO: inform caller
    }
  }

}