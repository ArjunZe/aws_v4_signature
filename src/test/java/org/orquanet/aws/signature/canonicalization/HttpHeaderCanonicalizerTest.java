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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class HttpHeaderCanonicalizerTest {

    private HttpHeaderCanonicalizer canonicalizer;
    private Map<String, Collection<String>> httpHeaders;

    @Before
    public void setUp() {
        canonicalizer = new HttpHeaderCanonicalizer();
        httpHeaders = new HashMap<>();
        httpHeaders.put("Host", Arrays.asList(" iam.amazon.com"));
        httpHeaders.put("Content-Type", Arrays.asList(" application/x-www-form-urlencoded; charset=utf-8"));
        httpHeaders.put("X-Amz-Date", Arrays.asList(" 20150830T123600Z"));
    }

    @Test
    public void testSignedHeader() {
        String signedHeaders = canonicalizer.getSignedHttpHeaders(httpHeaders);
        Assert.assertEquals("Signed headers should be equals", "content-type;host;x-amz-date", signedHeaders);
    }

}
