package fr.nta.security.http;


public class HttpAuthorizationException extends Exception {
	private static final long	serialVersionUID	= -8241168334311728923L;
	
	public HttpAuthorizationException(final String string, final Throwable e) {
		super(string, e);
	}
	public HttpAuthorizationException(final String string) {
		super(string);
	}
	public HttpAuthorizationException(final Throwable e) {
		super(e);
	}
	
}
