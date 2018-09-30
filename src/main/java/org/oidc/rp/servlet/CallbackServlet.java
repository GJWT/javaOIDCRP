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

package org.oidc.rp.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.rp.RPHandler;
import org.oidc.service.data.StateRecord;

@SuppressWarnings("serial")
public class CallbackServlet extends HttpServlet {

  private RPHandler handler;

  public CallbackServlet(RPHandler handler) {
    this.handler = handler;
  }

  @Override
  public void service(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // TODO: most of implementation and error handling. Only rough draft for now.
    String state = request.getParameter("state");
    StateRecord stateRecord = handler.getStateDb().getState(state);
    try {
      handler.finalize((String) stateRecord.getClaims().get("iss"), request.getParameterMap());
    } catch (MissingRequiredAttributeException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
  }

}
