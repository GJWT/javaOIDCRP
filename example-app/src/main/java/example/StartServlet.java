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

package example;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.oidc.common.MissingRequiredAttributeException;
import org.oidc.common.UnsupportedSerializationTypeException;
import org.oidc.msg.SerializationException;
import org.oidc.rp.RPBeginResponse;
import org.oidc.rp.RPHandler;
import org.oidc.service.base.RequestArgumentProcessingException;

public class StartServlet extends AbstractRpHandlerServlet {
  
  public static final String PARAM_NAME_ISSUER = "issuer";
  
  @Override
  public void service(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String issuer = request.getParameter(PARAM_NAME_ISSUER);
    if (issuer == null) {
      String html = "";
      for (String config : rpHandlers.keySet()) {
        html = html + "<p>" + config + ": " + rpHandlers.get(config).getOpConfiguration().getServiceContext().getIssuer() + "</p>";
      }
      String action = request.getContextPath() + ServletConfiguration.HOME_SERVLET_MAPPING;
      html = html + "<h1>Fill issuer here or give it in the URL parameter 'issuer'</h1>\n"
          + "<form method=\"GET\" action=\"" + action + "\">"
          + "  <input type=\"text\" name=\"issuer\" /><input type=\"submit\" name=\"OK\"/ >"
          + "</form>";
      writeHtmlBodyOutput(response, html);
      return;
    } else {
      
    }
    
    RPHandler rpHandler = getRpHandlerViaIssuer(issuer);
    if (rpHandler == null) {
      writeHtmlBodyOutput(response, "Could not find a configuration with the given issuer: " + issuer);
      return;
    }
    try {
      RPBeginResponse beginResponse = rpHandler.begin(issuer, null);
      if (beginResponse.getRedirectUri() != null) {
        response.sendRedirect(beginResponse.getRedirectUri());
      }
    } catch (MissingRequiredAttributeException | UnsupportedSerializationTypeException
        | RequestArgumentProcessingException | SerializationException e) {
      e.printStackTrace();
      writeHtmlBodyOutput(response, "Error: " + e.getMessage());
    }
  }
  
  protected RPHandler getRpHandlerViaIssuer(String issuer) {
    for (String config : rpHandlers.keySet()) {
      RPHandler rpHandler = rpHandlers.get(config);
      if (issuer.equals(rpHandler.getOpConfiguration().getServiceContext().getIssuer())) {
        return rpHandler;
      }
    }
    return null;
  }
  
  protected void writeHtmlBodyOutput(HttpServletResponse response, String output) throws IOException {
    PrintWriter writer = response.getWriter();
    writer.println("<html><body>");
    writer.println(output);
    writer.println("</body></html>");
    writer.close();    
  }

}
