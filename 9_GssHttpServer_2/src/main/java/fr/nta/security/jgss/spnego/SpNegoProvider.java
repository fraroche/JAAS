package fr.nta.security.jgss.spnego;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;


/**
 * @deprecated
 * 
 * Usage:<br>
 * <tt>
 * 		Security.addProvider(SpNegoProvider.INSTANCE);<br>
 * 		SpNegoProvider.seeProviderList();
 * </tt>
 */
public class SpNegoProvider extends Provider {
	
	public static final String		SPNEGO_OID			= "1.3.6.1.5.5.2";
	private static final String		SPNEGO_MECH_FACTORY	= SpNegoMechFactory.class.getName();
	private static final String		INFO				= "SpNego (Kerberos v5, SPNEGO)";
	private static final String		NAME				= "SpNegoJGSS";
	public static final SpNegoProvider	INSTANCE			= new SpNegoProvider();
	
	public SpNegoProvider() {
		super(NAME, 1.0D, INFO);
		AccessController.doPrivileged(
			new PrivilegedAction() {
				public Object run() {
					put("GssApiMechanism."+SPNEGO_OID, SPNEGO_MECH_FACTORY);
					return null;
				}
			}
		);
	}
	
	public static void seeProviderList() {
		final SecurityManager sm = System.getSecurityManager();
		final Provider[] p = Security.getProviders();
		for (int i = 0; i < p.length; i++) {
			System.out.println(p[i].toString()+" - "+p[i].getClass());
			final Enumeration keyList = p[i].keys();
			for (;keyList.hasMoreElements();) {
				final String key = (String) keyList.nextElement();
				final String val = p[i].getProperty(key);
				System.out.println("\t"+key+" - "+val);
			}
		}
	}
}
