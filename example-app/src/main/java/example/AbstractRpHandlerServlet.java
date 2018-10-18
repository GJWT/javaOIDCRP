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

import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import org.oidc.rp.RPHandler;

@SuppressWarnings("serial")
public abstract class AbstractRpHandlerServlet extends HttpServlet {

  protected Map<String, RPHandler> rpHandlers;

  @SuppressWarnings("unchecked")
  @Override
  public void init() throws ServletException {
    rpHandlers = (Map<String, RPHandler>) getServletConfig().getServletContext()
        .getAttribute(ServletConfiguration.ATTR_NAME_RP_HANDLERS);
    if (rpHandlers == null) {
      throw new ServletException("Could not find RPHandler instance from the servlet context!");
    }
  }

}
