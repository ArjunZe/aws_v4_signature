package org.orquanet.aws.signature.codec.binary;

import java.nio.charset.StandardCharsets;

public final class HexEncoder {

    private static final String HEX_SYMBOLS = "0123456789abcdef";

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
