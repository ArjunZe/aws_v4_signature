package org.orquanet.aws.signature.codec.digest;

public enum HashAlgorithm {

    SHA256("SHA-256", 32, "HMACSHA256");

    private String algorithmName;
    private int hashLength;
    private String macAlgorithmName;

    HashAlgorithm(final String algorithmName, final int hashLength, final String macAlgorithmName) {
        this.algorithmName = algorithmName;
        this.hashLength = hashLength;
        this.macAlgorithmName = macAlgorithmName;
    }

    public String algorithmName() {
        return this.algorithmName;
    }

    public int hashLength() {
        return this.hashLength;
    }

    public String macAlgorithmName() {
        return this.macAlgorithmName;
    }
}
