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

package org.orquanet.aws.signature.codec.binary;

import java.nio.charset.StandardCharsets;

public final class HexEncoder {

    private static final String HEX_SYMBOLS = "0123456789ABCDEF";

    public static String toHex(final byte[] data, int length) {

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            int v = data[i] & 0xff;
            //shift to the right and take the bottom 4 bits
            builder.append(HEX_SYMBOLS.charAt(v >> 4));
            builder.append(HEX_SYMBOLS.charAt(v & 0xf));
        }
        return builder.toString();
    }

    public static String toHex(final String data) {
        return toHex(data.getBytes(StandardCharsets.UTF_8), data.length());
    }
}
