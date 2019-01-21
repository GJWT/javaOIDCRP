package org.oidc.rp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.protocol.HttpContext;
import org.mockito.Mockito;

/**
 * Utility methods related to HTTP testing.
 */
public class HttpTestingSupport {
  
  public static CloseableHttpClient buildHttpClient(int statusCode, String body) 
      throws ClientProtocolException, IOException {
    CloseableHttpClient httpClient = Mockito.mock(CloseableHttpClient.class);
    CloseableHttpResponse httpResponse = Mockito.mock(CloseableHttpResponse.class);
    StatusLine statusLine = Mockito.mock(StatusLine.class);
    Mockito.when(statusLine.getStatusCode()).thenReturn(statusCode);
    Mockito.when(httpResponse.getStatusLine()).thenReturn(statusLine);
    StringEntity entity = new StringEntity(body);
    Mockito.when(httpResponse.getEntity()).thenReturn(entity);
    Mockito.when(httpClient.execute((HttpUriRequest) Mockito.any(), 
        (HttpContext) Mockito.any())).thenReturn(httpResponse);
    return httpClient;
  }

  public static String getMinimalOpConfigurationResponse(String issuer) {
    return "{\n" + "\"response_types_supported\": [\"id_token\"],\n"
        + "\"subject_types_supported\": [\"public\", \"pairwise\"],\n"
        + "\"id_token_signing_alg_values_supported\": [\n"
        + "    \"RS256\", \"RS384\", \"RS512\",\n" + "    \"ES256\", \"ES384\", \"ES512\",\n"
        + "    \"HS256\", \"HS384\", \"HS512\",\n"
        + "    \"PS256\", \"PS384\", \"PS512\", \"none\"],\n"
        + "\"issuer\": \"" + issuer + "\",\n"
        + "\"jwks_uri\": \"https://example.com/static/jwks_tE2iLbOAqXhe8bqh.json\",\n"
        + "\"authorization_endpoint\": \"https://example.com/authorization\"}";
  }
  
  public static String getMinimalWebfingerResponse(String subject, String issuer) {
    return "{\n" + 
        "   \"subject\" : \"" + subject + "\",\n" + 
        "   \"links\" :\n" + 
        "   [\n" + 
        "     {\n" + 
        "       \"rel\" : \"http://openid.net/specs/connect/1.0/issuer\",\n" + 
        "       \"href\" : \"" + issuer + "\"\n" + 
        "     }\n" + 
        "   ]\n" + 
        " }";
  }

}
