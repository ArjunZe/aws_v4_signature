package org.orquanet.aws.signature.codec.digest;

import org.orquanet.aws.signature.codec.binary.HexEncoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MacUtils {

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
