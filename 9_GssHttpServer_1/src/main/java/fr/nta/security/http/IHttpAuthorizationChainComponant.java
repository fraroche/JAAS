package fr.nta.security.http;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface IHttpAuthorizationChainComponant {
	public void doProcess(HttpServletRequest hreq, HttpServletResponse hres) throws HttpAuthorizationException;
}
