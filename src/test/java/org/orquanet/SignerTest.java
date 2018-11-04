package org.orquanet;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.orquanet.aws.signature.Signer;
import org.orquanet.aws.signature.HttpRequest;
import org.orquanet.aws.signature.SignatureInfo;
import org.orquanet.helpers.HttpRequestHelper;

import java.time.LocalDateTime;
import java.time.Month;
import java.util.stream.Collectors;

public class SignerTest {

    private LocalDateTime localDateTime;
    private final String EXPECTED_SIGNATURE = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";
    private final String SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    private final static String AWS_HASH_ALGORITHM = "AWS4-HMAC-SHA256";
    private final static String AWS_REGION = "us-east-1";
    private final static String AWS_SERVICE = "iam";

    @Before
    public void setUp() {
        localDateTime = LocalDateTime.of(2015, Month.AUGUST, 30, 12, 36, 00);
    }

    @Test
    public void testSign() throws Exception {

        HttpRequest request = HttpRequestHelper.create();

        Signer signer = Signer.builder()
                .regionName(AWS_REGION)
                .key(SECRET_KEY)
                .build();

        String signature = signer.sign(AWS_SERVICE, request, localDateTime);
        Assert.assertEquals("Signature should be equals", EXPECTED_SIGNATURE, signature);
    }

    @Test
    public void testSignatureInfo() throws Exception {

        HttpRequest request = HttpRequestHelper.create();

        String signedHeaders = request.getHeaders()
                .keySet()
                .stream()
                .map(h -> h.toLowerCase())
                .sorted()
                .collect(Collectors.joining(";"));

        Signer signer = Signer.builder()
                .regionName(AWS_REGION)
                .key(SECRET_KEY)
                .build();

        SignatureInfo signatureInfo = signer.signatureInfo(AWS_SERVICE, request, localDateTime);
        Assert.assertNotNull(signatureInfo);
        Assert.assertEquals("Signature should be equal", EXPECTED_SIGNATURE, signatureInfo.getSignature());
        Assert.assertEquals("Hash Algoritm should be equal", AWS_HASH_ALGORITHM, signatureInfo.getAlgorithm());
        Assert.assertEquals("Signed Headers should be equal", signedHeaders, signatureInfo.getSignedHeaders());
    }
}
