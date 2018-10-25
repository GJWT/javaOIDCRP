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

import org.oidc.msg.oidc.OpenIDSchema;

/** Class wrapping RP Handler finalize response. */
public class FinalizeResponse {

  /** State parameter. */
  private final String state;
  /** Error code. */
  private final String errorCode;
  /** Error description. */
  private final String errorDescription;
  /** Error uri. */
  private final String errorUri;
  /** User claims. */
  private final OpenIDSchema userClaims;
  /** Access token. */
  private final String accessToken;

  /**
   * Constructor.
   * 
   * @param state
   *          state parameter
   * @param errorCode
   *          error code
   * @param errorDescription
   *          error description
   * @param errorUri
   *          error uri
   */
  FinalizeResponse(String state, String errorCode, String errorDescription, String errorUri) {
    this.state = state;
    this.errorCode = errorCode;
    this.errorDescription = errorDescription;
    this.errorUri = errorUri;
    userClaims = null;
    accessToken = null;
  }

  /**
   * Constructor.
   * 
   * @param state
   *          state parameter
   * @param userClaims
   *          user claims
   * @param accessToken
   *          access token
   */
  FinalizeResponse(String state, OpenIDSchema userClaims, String accessToken) {
    this.state = state;
    this.userClaims = userClaims;
    this.accessToken = accessToken;
    errorCode = null;
    errorDescription = null;
    errorUri = null;
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
   * Get user claims.
   * 
   * @return user claims
   */
  public OpenIDSchema getUserClaims() {
    return userClaims;
  }

  /**
   * Get access token.
   * 
   * @return Access token
   */
  public String getAccessToken() {
    return accessToken;
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
