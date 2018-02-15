package fr.nta.security.gss.krb5;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import fr.nta.security.gss.GssClient;

public abstract class GssKrb5Client extends GssClient {

	protected String spn = null;
	
	public GssKrb5Client(final String SPN, final boolean conf, final boolean mutualAuth, final boolean replayDet, final boolean sequenceDet, final boolean integrity) {
		super(conf, mutualAuth, replayDet, sequenceDet, integrity);
		this.spn = SPN;
	}
	public GssKrb5Client(final String SPN) {
		super();
		this.spn = SPN;
	}

	public GSSContext computeContext() throws GSSException {
		final Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");
		final Oid krb5PrincipalNameType = new Oid("1.2.840.113554.1.2.2.1");
		final Oid spnegoMechOid  = new Oid("1.3.6.1.5.5.2");
		final GSSManager manager = GSSManager.getInstance();
		final GSSName serverName = manager.createName(spn, krb5PrincipalNameType);
		final GSSContext context = manager.createContext(serverName, krb5Oid, null, GSSContext.DEFAULT_LIFETIME);
		return context;
	}
}
