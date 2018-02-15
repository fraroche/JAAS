package sun.security.jgss;

import org.ietf.jgss.GSSException;

import sun.security.jgss.spi.GSSCredentialSpi;

/**
 * @deprecated
 * Could not have SpnegoCredential<br>
 * Only underlying authentication protocol creds should be instanciated.
 */
public class SpnegoCredential extends GSSCredentialImpl {
	
	/**
	 * @deprecated
	 * @param gssmanagerimpl
	 * @param gsscredentialspi
	 * @throws GSSException
	 */
	SpnegoCredential(final GSSManagerImpl gssmanagerimpl, final GSSCredentialSpi gsscredentialspi) throws GSSException {
		super(gssmanagerimpl, gsscredentialspi);
	}

}
