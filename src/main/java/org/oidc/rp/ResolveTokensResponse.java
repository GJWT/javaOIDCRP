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

import org.oidc.msg.oidc.IDToken;

/** Class wrapping RP Handler resolve tokens response. */
class ResolveTokensResponse extends AbstractResponse {

  /** Verified id token. */
  private final IDToken idToken;
  /** Access token. */
  private final String accessToken;
  /** Refresh token. */
  private final String refreshToken;

  /**
   * Constructor.
   * 
   * @param idToken
   *          Verified id token.
   * @param accessToken
   *          Access token.
   * @param refreshToken
   *          Refresh token.
   */
  ResolveTokensResponse(IDToken idToken, String accessToken, String refreshToken) {
    this.idToken = idToken;
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
  }

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
  ResolveTokensResponse(String state, String errorCode, String errorDescription, String errorUri) {
    super(state, errorCode, errorDescription, errorUri);
    idToken = null;
    accessToken = null;
    refreshToken = null;
  }

  /**
   * Get verified id token.
   * 
   * @return verified id token
   */
  public IDToken getIDToken() {
    return idToken;
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
