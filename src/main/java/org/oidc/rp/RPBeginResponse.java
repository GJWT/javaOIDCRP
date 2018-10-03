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

/** Class wrapping RP Handler begin response. */
public class RPBeginResponse {
  /** Redirect URI for authentication request. */
  final String redirectUri;
  /** State value the session is tied to. */
  final String state;

  /**
   * Constructor.
   * 
   * @param redirectUri
   *          redirect URI for authentication request
   * @param state
   *          state value the session is tied to
   */
  RPBeginResponse(String redirectUri, String state) {
    this.redirectUri = redirectUri;
    this.state = state;
  }

  /**
   * Get redirect URI for authentication request.
   * 
   * @return redirect URI for authentication request
   */
  public String getRedirectUri() {
    return redirectUri;
  }

  /**
   * Get state value the session is tied to.
   * 
   * @return state value the session is tied to
   */
  public String getState() {
    return state;
  }
}
