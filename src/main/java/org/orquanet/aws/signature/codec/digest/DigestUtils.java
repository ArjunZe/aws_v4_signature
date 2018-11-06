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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author xavier
 */
public final class DigestUtils {

    public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    public static final HashAlgorithm DEFAULT_DIGEST_ALGORITHM = HashAlgorithm.SHA256;

    public static byte[] hash(final String data) throws NoSuchAlgorithmException {
        return hash(data, DEFAULT_DIGEST_ALGORITHM,DEFAULT_CHARSET);
    }

    public static byte[] hash(final String data, final HashAlgorithm hashAlgorithm) throws NoSuchAlgorithmException {
        return hash(data,hashAlgorithm,DEFAULT_CHARSET);
    }

    public static byte[] hash(final String data, final Charset charset) throws NoSuchAlgorithmException {
        return hash(data,DEFAULT_DIGEST_ALGORITHM,charset);
    }

    public static byte[] hash(final String data, final HashAlgorithm hashAlgorithm,final Charset charset) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.algorithmName());
        return messageDigest.digest(data.getBytes(charset));
    }

    public static String hashHex(final String data) throws NoSuchAlgorithmException {
        return hashHex(data,DEFAULT_DIGEST_ALGORITHM,DEFAULT_CHARSET);
    }

    public static String hashHex(final String data,final HashAlgorithm hashAlgorithm) throws NoSuchAlgorithmException {
        return hashHex(data,hashAlgorithm,DEFAULT_CHARSET);
    }

    public static String hashHex(final String data,final Charset charset) throws NoSuchAlgorithmException {
        return hashHex(data,DEFAULT_DIGEST_ALGORITHM,charset);
    }

    public static String hashHex(final String data,final HashAlgorithm hashAlgorithm,final Charset charset) throws NoSuchAlgorithmException {
        return HexEncoder.toHex(hash(data,hashAlgorithm,charset),hashAlgorithm.hashLength());
    }
}
