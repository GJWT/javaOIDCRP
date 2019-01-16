/*
 * Copyright (C) 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package example;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import org.oidc.msg.DeserializationException;
import org.oidc.rp.config.OpConfiguration;
import org.oidc.rp.RPHandler;

public class ServletConfiguration implements ServletContainerInitializer {

  public static final String ATTR_NAME_RP_HANDLER = "oidcRpHandler";

  public static final String HOME_SERVLET_MAPPING = "/Home";

  @Override
  public void onStartup(Set<Class<?>> c, ServletContext servletContext) throws ServletException {

    String baseUrl = "https://127.0.0.1:8443/javaOIDCRP-example-app";

    ServletRegistration.Dynamic homeRegistration =
        servletContext.addServlet("home", new StartServlet());
    homeRegistration.addMapping(HOME_SERVLET_MAPPING);

    Map<String, OpConfiguration> opConfigs;
    try {
      opConfigs = OpConfiguration.parseFromJson("src/test/resources/testop_config.json", baseUrl);
      List<OpConfiguration> configurations = new ArrayList<>();
      for (String config : opConfigs.keySet()) {
        OpConfiguration opConfig = opConfigs.get(config);
        configurations.add(opConfig);
        for (String uri : opConfig.getServiceContext().getRedirectUris()) {
          System.out.println("URI: " + uri);
          ServletRegistration.Dynamic callbackRegistration =
              servletContext.addServlet(uri, new CallbackServlet(config));
          callbackRegistration.addMapping(uri.replace(baseUrl, ""));
        }
      }
      servletContext.setAttribute(ATTR_NAME_RP_HANDLER, new RPHandler(configurations));
    } catch (DeserializationException e) {
      e.printStackTrace();
    }
  }
}
