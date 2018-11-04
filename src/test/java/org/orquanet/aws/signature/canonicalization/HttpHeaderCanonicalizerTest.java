package org.orquanet.aws.signature.canonicalization;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class HttpHeaderCanonicalizerTest {

    private HttpHeaderCanonicalizer canonicalizer;
    private Map<String, String> httpHeaders;

    @Before
    public void setUp() {
        canonicalizer = new HttpHeaderCanonicalizer();
        httpHeaders = new HashMap<>();
        httpHeaders.put("Host", " iam.amazon.com");
        httpHeaders.put("Content-Type", " application/x-www-form-urlencoded; charset=utf-8");
        httpHeaders.put("X-Amz-Date", " 20150830T123600Z");
    }

    @Test
    public void testSignedHeader() {
        String signedHeaders = canonicalizer.getSignedHttpHeaders(httpHeaders);
        Assert.assertEquals("Signed headers should be equals", "content-type;host;x-amz-date", signedHeaders);
    }

}
