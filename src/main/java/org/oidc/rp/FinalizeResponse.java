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
public class FinalizeResponse extends AbstractResponse {

  /** User claims. */
  private final OpenIDSchema userClaims;
  
  /** Access token. */
  private final String accessToken;
  
  /** Refresh token. */
  private final String refreshToken;

  /**
   * Constructor.
   * 
   * @param state The state parameter.
   * @param errorCode The error code-
   * @param errorDescription The error description.
   * @param errorUri The error uri.
   */
  FinalizeResponse(String state, String errorCode, String errorDescription, String errorUri) {
    super(state, errorCode, errorDescription, errorUri);
    userClaims = null;
    accessToken = null;
    refreshToken = null;
  }

  /**
   * Constructor.
   * 
   * @param state The state parameter.
   * @param userClaims The user claims.
   * @param accessToken The access token.
   * @param refreshToken The refresh token.
   */
  FinalizeResponse(String state, OpenIDSchema userClaims, String accessToken, String refreshToken) {
    super(state, null, null, null);
    this.userClaims = userClaims;
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

  /**
   * Constructor.
   * 
   * @param response The response to copy the fields from. Must not be null.
   */
  FinalizeResponse(AbstractResponse response) {
    super(response);
    userClaims = null;
    accessToken = null;
    refreshToken = null;
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
   * Get refresh token.
   * 
   * @return Refresh token
   */
  public String getRefreshToken() {
    return refreshToken;
  }

}
