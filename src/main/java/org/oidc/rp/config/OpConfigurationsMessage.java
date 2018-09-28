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

package org.oidc.rp.config;

import java.util.Map;

import org.oidc.msg.AbstractMessage;
import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.ParameterVerification;
import org.oidc.msg.ParameterVerificationDefinition;
import org.oidc.msg.validator.ClaimValidator;

public class OpConfigurationsMessage extends AbstractMessage {

  public OpConfigurationsMessage(Map<String, Object> claims) {
    super(claims);
    for (String key : claims.keySet()) {
      paramVerDefs.put(key, new ParameterVerificationDefinition(new OpConfigurationValidator(), true));
    }
  }
  
  protected class SingleOpConfiguration extends AbstractMessage {
    
    {
      paramVerDefs.put("issuer", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
      paramVerDefs.put("client_id", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
      paramVerDefs.put("client_secret", ParameterVerification.SINGLE_OPTIONAL_STRING.getValue());
      paramVerDefs.put("redirect_uris", ParameterVerification.REQUIRED_LIST_OF_STRINGS.getValue());
    }

    public SingleOpConfiguration(Map<String, Object> claims) {
      super(claims);
    }

  }
  
  protected class OpConfigurationValidator implements ClaimValidator<Map<String, Object>> {

    @Override
    public Map<String, Object> validate(Object value) throws InvalidClaimException {
      if (!(value instanceof Map)) {
        throw new InvalidClaimException(
            String.format("Parameter '%s' is not of expected type", value));
      }
      Map<String, Object> map = (Map<String, Object>) value;
      SingleOpConfiguration opConfiguration = new SingleOpConfiguration(map);
      if (opConfiguration.verify()) {
        return map;
      }
      throw new InvalidClaimException("Invalid contents in the OP configuration");
    }
  }
}
