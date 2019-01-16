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

package org.oidc.rp;

/** Class implementing RP Handler error response. */
public abstract class AbstractResponse {

  /** State parameter. */
  protected final String state;
  
  /** Error code. */
  private final String errorCode;
  
  /** Error description. */
  private final String errorDescription;
  
  /** Error uri. */
  private final String errorUri;

  /**
   * Constructor.
   */
  AbstractResponse() {
    this(null, null, null, null);
  }

  /**
   * Constructor.
   * 
   * @param state The state parameter.
   * @param errorCode The error code.
   * @param errorDescription The error description.
   * @param errorUri The error uri.
   */
  AbstractResponse(String state, String errorCode, String errorDescription, String errorUri) {
    this.state = state;
    this.errorCode = errorCode;
    this.errorDescription = errorDescription;
    this.errorUri = errorUri;
  }

  /**
   * Constructor.
   * 
   * @param response The response to copy the fields from. Must not be null.
   */
  AbstractResponse(AbstractResponse response) {
    this(response.getState(), response.getErrorCode(), response.getErrorDescription(), 
        response.getErrorUri());
  }

  /**
   * Get state parameter.
   * 
   * @return state parameter
   */
  public String getState() {
    return state;
  }

  /**
   * Get error code.
   * 
   * @return error code
   */
  public String getErrorCode() {
    return errorCode;
  }

  /**
   * Get error description.
   * 
   * @return error description
   */
  public String getErrorDescription() {
    return errorDescription;
  }

  /**
   * Get error uri.
   * 
   * @return error uri
   */
  public String getErrorUri() {
    return errorUri;
  }

  /**
   * Whether the response is a error response.
   * 
   * @return whether the response is a error response
   */
  public boolean indicatesError() {
    return errorCode != null;
  }

}
