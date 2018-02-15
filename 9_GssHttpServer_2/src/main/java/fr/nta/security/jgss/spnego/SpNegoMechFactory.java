package fr.nta.security.jgss.spnego;

import java.security.Provider;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;


import sun.security.jgss.spi.GSSContextSpi;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;
import sun.security.jgss.spi.MechanismFactory;
/**
 * @deprecated
 * This class is no more used since spnego management is now achieved in higher level classes: SpnegoManager-SpnegoContext
 */
public class SpNegoMechFactory implements MechanismFactory {
	static final Provider	PROVIDER			= SpNegoProvider.INSTANCE;
	static final Oid		GSS_SPNEGO_MECH_OID	= createOid(SpNegoProvider.SPNEGO_OID);

	public GSSCredentialSpi getCredentialElement(final GSSNameSpi gssnamespi, final int i, final int j, final int k) throws GSSException {
System.out.println("getCredentialElement()");
System.out.println(i);
System.out.println(j);
System.out.println(k);
System.out.println(gssnamespi.getMechanism());

System.out.println(this.getClass().getName()+" - "+ new String(gssnamespi.export()));
		return null;
	}

	public GSSContextSpi getMechanismContext(final GSSCredentialSpi gsscredentialspi) throws GSSException {
		return null;
	}

	public GSSContextSpi getMechanismContext(final byte[] abyte0) throws GSSException {
		return null;
	}

	public GSSContextSpi getMechanismContext(final GSSNameSpi gssnamespi, final GSSCredentialSpi gsscredentialspi, final int i) throws GSSException {
		return null;
	}

	public Oid getMechanismOid() {
		return null;
	}

	public GSSNameSpi getNameElement(final String s, final Oid oid) throws GSSException {
		return null;
	}

	public GSSNameSpi getNameElement(final byte[] abyte0, final Oid oid) throws GSSException {
		return null;
	}

	public Oid[] getNameTypes() {
		return null;
	}

	public Provider getProvider() {
		return PROVIDER;
	}

	private static Oid createOid(final String s) {
		Oid oid = null;
		try {
			oid = new Oid(s);
		} catch (final GSSException gssexception) {
		}
		return oid;
	}
}
