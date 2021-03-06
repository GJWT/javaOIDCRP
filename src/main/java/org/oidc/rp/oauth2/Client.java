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

package org.oidc.rp.oauth2;

import org.oidc.rp.config.OpConfiguration;
import org.oidc.service.base.ServiceContext;

/**
 * The client holding state and configuration for the communication with the remote AS/OP.
 */
public class Client {
  
  /** The configuration for the remote AS/OP. */
  private OpConfiguration opConfiguration;

  /**
   * Constructor.
   * 
   * @param configuration The configuration for the remote AS/OP.
   */
  public Client(OpConfiguration configuration) {
    opConfiguration = configuration;
  }
  
  /**
   * Get the service context information from the OP configuration.
   * 
   * @return The service context information from the OP configuration.
   */
  public ServiceContext getServiceContext() {
    return opConfiguration.getServiceContext();
  }
  
  /**
   * Get the configuration for the remote AS/OP.
   * 
   * @return The configuration for the remote AS/OP.
   */
  public OpConfiguration getOpConfiguration() {
    return opConfiguration;
  }
  
  /**
   * Set the configuration for the remote AS/OP.
   * @param configuration What to set.
   */
  public void setOpConfiguration(OpConfiguration configuration) {
    opConfiguration = configuration;
  }

}
