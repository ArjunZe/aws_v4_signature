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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.Month;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class AWSV4TestSuite {

	public static final String ROOT_AWS_TEST_SUITE = "aws-sig-v4-test-suite";
	public static final String REGION = "us-east-1";
	public static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
	public static final LocalDateTime AWS_REQUEST_DATE_TIME = LocalDateTime.of(2015, Month.AUGUST, 30, 12, 36, 00);
	public static final String SERVICE = "service";
	public static final String EMPTY_STRING = "";

	private Signer signer;

	private Path testDirectory;

	public AWSV4TestSuite(Path path) {
		this.testDirectory = path;
	}

	@Before
	public void setUp() {
		signer = Signer.builder().regionName(REGION).key(AWS_SECRET_KEY).build();
	}

	@Parameters()
	public static Collection<Path> path() throws IOException {
		Path awsTestSuiteRootPath = Paths.get(Thread.currentThread().getContextClassLoader().getResource(ROOT_AWS_TEST_SUITE).getPath());
		return Files.find(awsTestSuiteRootPath, 2, (path, bfa) -> bfa.isDirectory() && isTestDirectory(path), FileVisitOption.FOLLOW_LINKS).collect(Collectors.toList());
	}

	@Test
	public void testCanonicalRequest() throws IOException {

		HttpRequest request = buildHttpRequest(testDirectory);
		String expectedCanonicalRequest = getCanonicalRequest(testDirectory);
		String actualCanonicalRequest = signer.canonicalRequest(request,SERVICE);
		assertThat("Canonical Requests should be the same", actualCanonicalRequest, equalTo(expectedCanonicalRequest));
	}

	public String getCanonicalRequest(Path testDirectory) throws IOException {
		Path fileName = testDirectory.getFileName();
		Path requestTestFile = Paths.get(testDirectory.toString(), fileName.toString() + ".creq");
		return Files.lines(requestTestFile).collect(Collectors.joining("\n"));

	}

	@Test
	public void testStringToSign() throws IOException {

		HttpRequest request = buildHttpRequest(testDirectory);
		Signer signer = Signer.builder().regionName(REGION).key(AWS_SECRET_KEY).build();
		String actualStringToSign = signer.stringToSign(SERVICE, request, AWS_REQUEST_DATE_TIME);
		String expectedStringToSign = getStringToSign(testDirectory);
		assertThat("String to sign should be equals", actualStringToSign, equalTo(expectedStringToSign));
	}

	@Test
	public void testSignatureserviceName() throws IOException {
		HttpRequest request = buildHttpRequest(testDirectory);
		Signer signer = Signer.builder().regionName(REGION).key(AWS_SECRET_KEY).build();

		SignatureInfo signatureInfo = signer.signatureInfo(SERVICE, request, AWS_REQUEST_DATE_TIME);

		String expectedSignature = getSignature(testDirectory);
		String actualSignature = signatureInfo.getSignature();
		assertThat("String to sign should be equals", actualSignature, equalTo(expectedSignature));

	}

	public String getSignature(Path testDirectory) throws IOException {
		Path fileName = testDirectory.getFileName();
		Path requestTestFile = Paths.get(testDirectory.toString(), fileName.toString() + ".authz");
		String sign = Files.lines(requestTestFile).findFirst().map((s) -> s.replaceAll(".*Signature=", "")).get();
		return sign;

	}

	public String getStringToSign(Path testDirectory) throws IOException {
		Path fileName = testDirectory.getFileName();
		Path requestTestFile = Paths.get(testDirectory.toString(), fileName.toString() + ".sts");
		String content = Files.lines(requestTestFile).collect(Collectors.joining("\n"));
		return content;

	}

	public HttpRequest buildHttpRequest(Path pathTestDirectory) throws IOException {
		Path fileName = pathTestDirectory.getFileName();
		Path requestTestFile = Paths.get(pathTestDirectory.toString(), fileName.toString() + ".req");

		List<String> fileLines = Files.lines(Paths.get(requestTestFile.toString())).collect(Collectors.toList());

		// build request line
		String requestLine = fileLines.remove(0);

		requestLine = requestLine.substring(0, requestLine.lastIndexOf(" "));
		String[] requestLineChunks = requestLine.split(" ", 2);
		
		//get method
		String method = requestLineChunks[0];
		String requestURI = requestLineChunks[1];
		
		// get path and query parameters
		String[] pathQueryKV = requestURI.split("\\?");

		// get path
		String path = pathQueryKV[0];

		//get query parameters
		String queryParameters = (pathQueryKV.length > 1)?pathQueryKV[1]:"";

		//get headers
		Iterator<String> fileIterator = fileLines.iterator();
		Map<String, Collection<String>> headers = parseHeaders(fileIterator);

		// get payload
		String payload = EMPTY_STRING;
		if (fileIterator.hasNext()) {
			payload = fileIterator.next();

		}

		HttpRequest httpRequest = HttpRequest.builder().headers(headers).method(method).payload(payload).path(path).parameters(queryParameters).build();

		return httpRequest;
	}

	public Map<String, Collection<String>> parseHeaders(Iterator<String> it) {
		boolean crlfFound = false;
		String headerValue = null;
		String headerName = null;

		Map<String, Collection<String>> headers = new HashMap<>();
		while (it.hasNext() && !crlfFound) {
			String line = it.next();
			if (EMPTY_STRING.equals(line.trim())) {
				crlfFound = true;
			} else {
				if (line.startsWith(" ")) {
					headerValue = line;

				} else {
					String[] headersSplit = line.split(":");
					headerValue = headersSplit.length > 1 ? headersSplit[1] : null;
					headerName = headersSplit[0];

					if (!headers.containsKey(headerName)) {
						headers.put(headerName, new ArrayList<>());
					}
				}
				headers.get(headerName).add(headerValue);

			}
		}
		return headers;

	}

	private static boolean isTestDirectory(Path path) {
		boolean containsTestFiles = false;
		try {
			containsTestFiles = !Files.list(path).anyMatch(x -> Files.isDirectory(x));
		} catch (IOException e) {
			throw new RuntimeException();
		}
		return containsTestFiles;
	}
}
