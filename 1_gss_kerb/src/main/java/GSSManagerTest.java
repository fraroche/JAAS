import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class GSSManagerTest {
	public static void main(final String[] args) throws GSSException {
		final GSSManager manager = GSSManager.getInstance();

		final Oid krb5Mechanism = new Oid("1.2.840.113554.1.2.2");
		final Oid krb5PrincipalNameType = new Oid("1.2.840.113554.1.2.2.1");

		// Identify who the client wishes to be
		final GSSName userName = manager.createName("ut11am", GSSName.NT_USER_NAME);

		// Identify the name of the server. This uses a Kerberos specific
		// name format.
		final GSSName serverName = manager.createName("nfs/foo.sun.com", krb5PrincipalNameType);

		// Acquire credentials for the user
		final GSSCredential userCreds = manager.createCredential(userName, GSSCredential.DEFAULT_LIFETIME, krb5Mechanism, GSSCredential.INITIATE_ONLY);

		// Instantiate and initialize a security context that will be
		// established with the server
		final GSSContext context = manager.createContext(serverName, krb5Mechanism, userCreds, GSSContext.DEFAULT_LIFETIME);
		
		System.out.println(context);
	}
}
