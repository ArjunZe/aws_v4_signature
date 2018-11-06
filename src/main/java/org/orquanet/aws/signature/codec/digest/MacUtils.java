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

package org.orquanet.aws.signature.codec.digest;

import org.orquanet.aws.signature.codec.binary.HexEncoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public final class MacUtils {

    public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    public static final HashAlgorithm DEFAULT_ALGORITHM = HashAlgorithm.SHA256;

    public static byte[] hmac(final String data, final byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
        return hmac(data, key, DEFAULT_ALGORITHM, DEFAULT_CHARSET);
    }

    public static byte[] hmac(final String data, final byte[] key, final HashAlgorithm hashAlgorithm) throws
            InvalidKeyException, NoSuchAlgorithmException {
        return hmac(data, key, hashAlgorithm, DEFAULT_CHARSET);
    }

    public static byte[] hmac(final String data, final byte[] key, Charset charset) throws InvalidKeyException, NoSuchAlgorithmException {
        return hmac(data, key, DEFAULT_ALGORITHM, charset);
    }

    public static byte[] hmac(final String data, byte[] key, final HashAlgorithm hashAlgorithm, final Charset charset) throws InvalidKeyException, NoSuchAlgorithmException {
        String algorithmName = hashAlgorithm.macAlgorithmName();
        Mac mac = Mac.getInstance(algorithmName);
        mac.init(new SecretKeySpec(key, algorithmName));
        return mac.doFinal(data.getBytes(charset));
    }

    public static String hmacHex(final String data, final byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacHex(data, key, DEFAULT_ALGORITHM, DEFAULT_CHARSET);
    }

    public static String hmacHex(final String data, final byte[] key, final HashAlgorithm hashAlgorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        return hmacHex(data, key, hashAlgorithm, DEFAULT_CHARSET);
    }

    public static String hmacHex(final String data, final byte[] key, final Charset charset) throws
            NoSuchAlgorithmException, InvalidKeyException {
        return hmacHex(data, key, DEFAULT_ALGORITHM, charset);
    }

    public static String hmacHex(final String data,final  byte[] key, final HashAlgorithm hashAlgorithm, final Charset charset) throws
            NoSuchAlgorithmException, InvalidKeyException {
        return HexEncoder.toHex(hmac(data, key, hashAlgorithm), hashAlgorithm.hashLength());
    }
}
