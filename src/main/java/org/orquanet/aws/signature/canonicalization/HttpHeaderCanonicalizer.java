package org.orquanet.aws.signature.canonicalization;

import org.orquanet.aws.signature.canonicalization.exception.CanonicalizerException;

import java.util.Map;
import java.util.stream.Collectors;

class HttpHeaderCanonicalizer {

    public String getSignedHttpHeaders(final Map<String, String> httpHeaders) {
        if (httpHeaders == null || httpHeaders.isEmpty()) {
            throw new CanonicalizerException("Missing http headers");
        }

        return httpHeaders.keySet().stream()
                .map(k -> k.toLowerCase())
                .sorted()
                .collect(Collectors.joining(";"));
    }

    public String canonicalize(final Map<String, String> httpHeaders) {

        if (httpHeaders == null || httpHeaders.isEmpty()) {
            throw new CanonicalizerException("Missing http headers");
        }

        return httpHeaders.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> String.format("%s:%s\n", e.getKey().toLowerCase(), e.getValue() == null ? "" : e.getValue().trim()))
                .collect(Collectors.joining());
    }
}
