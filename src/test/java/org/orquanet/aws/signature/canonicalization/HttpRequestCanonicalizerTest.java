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
    private final String SERVICE = "service";
    @Before
    public void setUp() {
        canonicalizer = new HttpRequestCanonicalizer();
    }

    @Test
    public void testCanonicalizeRequest() throws Exception {
        HttpRequest httpRequest = HttpRequestHelper.create();
        String canonicalRequest = canonicalizer.canonicalize(httpRequest, SERVICE);

        String canonicalRequestDigest = HexEncoder.toHex(DigestUtils.hash(canonicalRequest, HashAlgorithm.SHA256), HashAlgorithm.SHA256.hashLength()).toLowerCase();
        LOGGER.info(canonicalRequest);
        LOGGER.info(String.format("Canonical Request Digest: %s", canonicalRequestDigest));

        Assert.assertEquals("Canonical request Hash should be the same", EXPECTED_CANONICALREQUEST_HASH, canonicalRequestDigest);
    }
}
