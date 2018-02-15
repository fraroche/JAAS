package fr.nta.security.jgss.spnego;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;

import sun.security.jgss.GSSManagerImpl;
import sun.security.jgss.SpnegoContext;

public class SpnegoManager extends GSSManagerImpl {
	public static GSSManager getInstance() {
		return new SpnegoManager();
	}
	
	public GSSContext createContext(final byte[] interProcessToken) throws GSSException {
		final GSSContext gssContext = GSSManager.getInstance().createContext(interProcessToken);
		return new SpnegoContext(gssContext);
	}
}
