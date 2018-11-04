package org.orquanet.aws.signature.exception;

public class SigningException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public SigningException() {
        super();
    }
    public SigningException(String s) {
        super(s);
    }

    public SigningException(String s, Throwable throwable) {
        super(s, throwable);
    }

    public SigningException(Throwable throwable) {
        super(throwable);
    }

    protected SigningException(String s, Throwable throwable, boolean b, boolean b1) {
        super(s, throwable, b, b1);
    }
}
