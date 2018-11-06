/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.orquanet.aws.signature.canonicalization;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import org.orquanet.aws.signature.HttpRequest;
import org.orquanet.aws.signature.canonicalization.exception.CanonicalizerException;
import org.orquanet.aws.signature.codec.digest.DigestUtils;
import org.orquanet.aws.signature.codec.text.URIEncoder;

final class HttpRequestCanonicalizer {

    private HttpHeaderCanonicalizer httpHeaderCanonicalizer;

    public HttpRequestCanonicalizer() {
        super();
        httpHeaderCanonicalizer = new HttpHeaderCanonicalizer();
    }

    public String canonicalizePath(final String path,String service) throws URISyntaxException{
        if (path == null || path.isEmpty()) {
            return "/";
        }
        
        String encodedPath = URIEncoder.encode(path, URIEncoder.PATH_UNESCAPED);
        return new URI("http://blabla.org" + encodedPath).normalize().getRawPath();
    }

    public String canonicalizeQuery(final String query) {

        if (query == null || query.isEmpty()) {
            return "";
        }

        Map<String, Collection<String>> parametersMap = extractQueryParameters(query);
        return parametersMap.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .flatMap(e -> e.getValue().stream().map(v -> String.format("%s=%s",  URIEncoder.encode(e.getKey(),URIEncoder.QUERY_PARAMETERS_UNESCAPED), URIEncoder.encode(v, URIEncoder.QUERY_PARAMETERS_UNESCAPED))))
                .collect(Collectors.joining("&"));
    }

    public Map<String, Collection<String>> extractQueryParameters(final String query) {

        TreeMap<String, Collection<String>> parametersMap = new TreeMap<>();

        if (query != null && !query.isEmpty()) {
            String[] queryParameters = query.split("&");
            Arrays.stream(queryParameters).forEach(queryParameter -> {
                String[] parameterKV = queryParameter.split("=");
                String parameterName = parameterKV[0];
                String parameterValue = parameterKV.length > 1 ? parameterKV[1] : "";
                if (parametersMap.containsKey(parameterName)) {
                    parametersMap.get(parameterName).add(parameterValue);
                } else {
                    TreeSet<String> parameterValues = new TreeSet<>();
                    parameterValues.add(parameterValue);
                    parametersMap.put(parameterName, parameterValues);
                }

            });
        }
        return parametersMap;
    }


    public String canonicalize(HttpRequest request,String service) {

        String canonicalRequest;

        try {
            String method = request.getMethod();
            String canonicalPath = canonicalizePath(request.getPath(),service);
            String parameters = request.getParameters();
            String canonicalQueryParameters = canonicalizeQuery(parameters);

            String canonicalHeaders = httpHeaderCanonicalizer.canonicalize(request.getHeaders());
            String signedHeaders = httpHeaderCanonicalizer.getSignedHttpHeaders(request.getHeaders());

            String hashedPayload = DigestUtils.hashHex(request.getPayload());

            canonicalRequest = String.format("%s\n%s\n%s\n%s\n%s\n%s",
                    method,
                    canonicalPath,
                    canonicalQueryParameters,
                    canonicalHeaders,
                    signedHeaders,
                    hashedPayload.toLowerCase());
        } catch (NoSuchAlgorithmException e) {
            throw new CanonicalizerException(e);
        } catch (Exception e) {
            throw new CanonicalizerException(e);
        }

        return canonicalRequest;
    }
}
