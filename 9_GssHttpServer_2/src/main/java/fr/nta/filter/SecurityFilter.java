package fr.nta.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import fr.nta.security.http.HttpAuthorizationException;
import fr.nta.security.http.IHttpAuthorizationChainComponant;
import fr.nta.security.http.spnego.SpnegoAuthenticator;

public class SecurityFilter implements IHttpAuthorizationChainComponant, Filter {

	private FilterChain chain;
	private IHttpAuthorizationChainComponant securityCheker;
	
	public void doProcess(final HttpServletRequest hreq, final HttpServletResponse hres) throws HttpAuthorizationException {
		try {
			chain.doFilter(hreq, hres);
		} catch (final IOException e) {
			throw new HttpAuthorizationException("IOException", e);
		} catch (final ServletException e) {
			throw new HttpAuthorizationException("ServletException", e);
		}
	}
	
	public void destroy() {
	}
	
	public void init(final FilterConfig arg0) throws ServletException {
		this.securityCheker = new SpnegoAuthenticator(this);
	}
	
	public void doFilter(final ServletRequest req, final ServletResponse resp, final FilterChain chain) throws IOException, ServletException {
		this.chain = chain;
		try {
			securityCheker.doProcess((HttpServletRequest)req, (HttpServletResponse)resp);
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
}
