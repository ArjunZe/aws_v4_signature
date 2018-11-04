package org.orquanet.aws.signature.canonicalization;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.orquanet.aws.signature.HttpRequest;
import org.orquanet.aws.signature.codec.digest.HashAlgorithm;
import org.orquanet.helpers.HttpRequestHelper;
import org.orquanet.aws.signature.codec.binary.HexEncoder;
import org.orquanet.aws.signature.codec.digest.DigestUtils;

import java.util.logging.Logger;

public class HttpRequestCanonicalizerTest {

    private HttpRequestCanonicalizer canonicalizer;

    private Logger LOGGER = Logger.getLogger(this.getClass().toString());
    private static final String EXPECTED_CANONICALREQUEST_HASH = "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";

    @Before
    public void setUp() {
        canonicalizer = new HttpRequestCanonicalizer();
    }

    @Test
    public void testCanonicalizeRequest() throws Exception {
        HttpRequest httpRequest = HttpRequestHelper.create();
        String canonicalRequest = canonicalizer.canonicalize(httpRequest);

        String canonicalRequestDigest = HexEncoder.toHex(DigestUtils.hash(canonicalRequest, HashAlgorithm.SHA256), HashAlgorithm.SHA256.hashLength());
        LOGGER.info(canonicalRequest);
        LOGGER.info(String.format("Canonical Request Digest: %s", canonicalRequestDigest));

        Assert.assertEquals("Canonical request Hash should be the same", EXPECTED_CANONICALREQUEST_HASH, canonicalRequestDigest);
    }
}
