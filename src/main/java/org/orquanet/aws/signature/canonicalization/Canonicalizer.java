package org.orquanet.aws.signature.canonicalization;

import org.orquanet.aws.signature.HttpRequest;

import java.util.Map;

public class Canonicalizer {

    private HttpHeaderCanonicalizer headerCanonicalizer;
    private HttpRequestCanonicalizer requestCanonicalizer;

    public Canonicalizer(){
        headerCanonicalizer = new HttpHeaderCanonicalizer();
        requestCanonicalizer = new HttpRequestCanonicalizer();
    }

    public String getCanonicalRequest(final HttpRequest httpRequest) {
        return requestCanonicalizer.canonicalize(httpRequest);
    }

    public String getCanonicalHeaders(final HttpRequest httpRequest){
        Map<String,String> headers = httpRequest.getHeaders();
        return headerCanonicalizer.canonicalize(headers);
    }

    public String getSignedHeaders(final HttpRequest httpRequest) {
        Map<String,String> headers = httpRequest.getHeaders();
        return headerCanonicalizer.getSignedHttpHeaders(headers);
    }
}
