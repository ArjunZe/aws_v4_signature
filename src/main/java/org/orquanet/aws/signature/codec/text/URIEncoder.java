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

package org.orquanet.aws.signature.codec.text;

import java.io.ByteArrayOutputStream;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.BitSet;

import org.orquanet.aws.signature.codec.binary.HexEncoder;

public class URIEncoder {

	public static final BitSet QUERY_PARAMETERS_UNESCAPED;
	public static final BitSet PATH_UNESCAPED;
	static {
		BitSet unreserved = new BitSet();
		for (int i = 'a'; i <= 'z'; i++) {
			unreserved.set(i);
		}

		for (int i = 'A'; i <= 'Z'; i++) {
			unreserved.set(i);
		}

		for (int i = '0'; i <= '9'; i++) {
			unreserved.set(i);
		}

		unreserved.set('-');
		unreserved.set('_');
		unreserved.set('.');
		unreserved.set('~');

		PATH_UNESCAPED = new BitSet();
		PATH_UNESCAPED.set('/');
		PATH_UNESCAPED.or(unreserved);

		QUERY_PARAMETERS_UNESCAPED = new BitSet();
		QUERY_PARAMETERS_UNESCAPED.or(unreserved);
	}

	public static String encode(String value, BitSet unescapedChars) {
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		for (final byte c : value.getBytes(StandardCharsets.UTF_8)) {
			int b = c;
			if (b < 0) {
				b = b & 0xff;
			}
			if (unescapedChars.get(b)) {
				buffer.write(b);
			} else {
				buffer.write('%');
				String t = HexEncoder.toHex(new byte[] { (byte) b }, 1);
				CharBuffer.wrap(t.toCharArray()).chars().forEach((c1) -> buffer.write(c1));
			}
		}
		String myString = new String(buffer.toByteArray(), StandardCharsets.UTF_8);
		return myString;
	}

/*	public static void main(String args[]) {
		encode("peé! opሴ", QUERY_PARAMETERS_UNESCAPED);
	}
	*/
}
