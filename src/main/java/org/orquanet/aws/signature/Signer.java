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

package org.orquanet.aws.signature;

import org.orquanet.aws.signature.canonicalization.Canonicalizer;
import org.orquanet.aws.signature.codec.binary.HexEncoder;
import org.orquanet.aws.signature.codec.digest.DigestUtils;
import org.orquanet.aws.signature.codec.digest.HashAlgorithm;
import org.orquanet.aws.signature.codec.digest.MacUtils;
import org.orquanet.aws.signature.exception.SigningException;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class Signer {

	private final static String AWS_HASH_ALGORITHM = "AWS4-HMAC-SHA256";
	private final static String AWS_DATE_TIME_ISO8601_FORMAT = "yyyyMMdd'T'HHmmss'Z'";

	private Canonicalizer canonicalizer;
	private String regionName;
	private String key;

	public Signer() {
		super();
		this.canonicalizer = new Canonicalizer();
	}

	public SignatureInfo signatureInfo(final String serviceName, final HttpRequest httpRequest) {
		return this.signatureInfo(serviceName, httpRequest, LocalDateTime.now());
	}

	public SignatureInfo signatureInfo(final String serviceName, final HttpRequest httpRequest, final LocalDateTime localDateTime) {

		SignatureInfo signatureInfo;
		try {
			String signature = this.sign(serviceName, httpRequest, localDateTime);
			String signedHeaders = this.canonicalizer.getSignedHeaders(httpRequest);

			signatureInfo = SignatureInfo.builder().signature(signature.toLowerCase()).algorithm(AWS_HASH_ALGORITHM).signedHeaders(signedHeaders).build();
		} catch (Exception e) {
			throw new SigningException(e);
		}
		return signatureInfo;
	}

	public String sign(final String serviceName, final HttpRequest httpRequest) throws Exception {
		return this.sign(serviceName, httpRequest, LocalDateTime.now());
	}

	public String canonicalRequest(final HttpRequest httpRequest, String service) {
		return canonicalizer.getCanonicalRequest(httpRequest, service);

	}

	public String stringToSign(final String serviceName, final HttpRequest httpRequest, final LocalDateTime localDateTime) {
		try {
			String canonicalRequest = canonicalRequest(httpRequest, serviceName);

			String canonicalRequestDigest = HexEncoder.toHex(DigestUtils.hash(canonicalRequest, HashAlgorithm.SHA256), HashAlgorithm.SHA256.hashLength());

			DateTimeFormatter dateTimeFormat = DateTimeFormatter.ofPattern(AWS_DATE_TIME_ISO8601_FORMAT);
			String dateTime = dateTimeFormat.format(localDateTime);

			DateTimeFormatter dateFormat = DateTimeFormatter.BASIC_ISO_DATE;
			String date = dateFormat.format(localDateTime);

			return String.format("%s\n%s\n%s/%s/%s/aws4_request\n%s", AWS_HASH_ALGORITHM, dateTime, date, this.regionName, serviceName, canonicalRequestDigest.toLowerCase());
		} catch (Exception e) {
			throw new SigningException(e);
		}
	}

	public String sign(final String serviceName, final HttpRequest httpRequest, final LocalDateTime localDateTime) {
		try {
			String stringToSign = stringToSign(serviceName, httpRequest, localDateTime);
			DateTimeFormatter dateFormat = DateTimeFormatter.BASIC_ISO_DATE;
			String date = dateFormat.format(localDateTime);

			byte[] signatureKey = getSignatureKey(serviceName, date);
			return MacUtils.hmacHex(stringToSign, signatureKey).toLowerCase();
		} catch (Exception e) {
			throw new SigningException(e);
		}
	}

	public byte[] getSignatureKey(final String serviceName, final String dateTime) {
		byte[] kSigning;
		try {
			byte[] kSecret = (String.format("AWS4%s", this.key)).getBytes(StandardCharsets.UTF_8);
			byte[] kDate = MacUtils.hmac(dateTime, kSecret);
			byte[] kRegion = MacUtils.hmac(this.regionName, kDate, HashAlgorithm.SHA256);
			byte[] kService = MacUtils.hmac(serviceName, kRegion, HashAlgorithm.SHA256);
			kSigning = MacUtils.hmac("aws4_request", kService, HashAlgorithm.SHA256);
		} catch (Exception e) {
			throw new SigningException(e);
		}
		return kSigning;
	}

	public byte[] getSignatureKey(final String serviceName, final LocalDateTime localDateTime) {
		DateTimeFormatter format = DateTimeFormatter.ofPattern(AWS_DATE_TIME_ISO8601_FORMAT);
		String dateTime = format.format(localDateTime);
		return this.getSignatureKey(serviceName, dateTime);
	}

	public static Builder builder() {
		return new Signer.Builder();
	}

	public static class Builder {

		private Signer signer = new Signer();

		public Builder regionName(final String regionName) {
			this.signer.regionName = regionName;
			return this;
		}

		public Builder key(final String key) {
			this.signer.key = key;
			return this;
		}

		public Signer build() {
			return this.signer;
		}
	}
}
