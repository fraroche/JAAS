package fr.nta.security.http;


public abstract class HttpAuthorizationDecorator implements IHttpAuthorizationChainComponant {

	protected final IHttpAuthorizationChainComponant	nextComponant;

	public HttpAuthorizationDecorator(final IHttpAuthorizationChainComponant nextSecurityFilter) {
		this.nextComponant = nextSecurityFilter;
	}
}
