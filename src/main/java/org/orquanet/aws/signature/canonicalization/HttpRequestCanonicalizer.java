package org.orquanet.aws.signature.canonicalization;

import org.orquanet.aws.signature.canonicalization.exception.CanonicalizerException;
import org.orquanet.aws.signature.codec.digest.DigestUtils;
import org.orquanet.aws.signature.HttpRequest;

import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

class HttpRequestCanonicalizer {

    private HttpHeaderCanonicalizer httpHeaderCanonicalizer;

    public HttpRequestCanonicalizer() {
        super();
        httpHeaderCanonicalizer = new HttpHeaderCanonicalizer();
    }

    public String canonicalizePath(final String path) {
        String canonicalPath = path;
        if (path == null || path.isEmpty()) {
            return "/";
        }
        
        // TBD
        return canonicalPath;
    }

    public String canonicalizeQuery(final String query) {

        if (query == null || query.isEmpty()) {
            return "/";
        }

        Map<String, Collection<String>> parametersMap = extractQueryParameters(query);
        return parametersMap.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .flatMap(e -> e.getValue().stream().map(v -> String.format("%s=%s", e.getKey(), v)))
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


    public String canonicalize(HttpRequest request) {

        String canonicalRequest;

        try {
            String method = request.getMethod();
            String canonicalPath = canonicalizePath(request.getPath());
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
                    hashedPayload);
        } catch (NoSuchAlgorithmException e) {
            throw new CanonicalizerException(e);
        } catch (Exception e) {
            throw new CanonicalizerException(e);
        }

        return canonicalRequest;
    }
}
