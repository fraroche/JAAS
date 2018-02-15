import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class GSSCredentialTest {
	public static void main(final String[] args) throws GSSException {
		final GSSManager manager = GSSManager.getInstance();

		// start by creating a name object for the entity
		final GSSName name = manager.createName("HTTP/cmxd5014.dev.cm.par.emea.cib@CM.PAR.EMEA.CIB", GSSName.NT_USER_NAME);

		// now acquire credentials for the entity
		final GSSCredential cred = manager.createCredential(name, GSSCredential.INDEFINITE_LIFETIME, (Oid) null, GSSCredential.ACCEPT_ONLY);

		// display credential information - name, remaining lifetime,
		// and the mechanisms it has been acquired over
		System.out.println(cred.getName().toString());
		System.out.println(cred.getRemainingLifetime());

		final Oid[] mechs = cred.getMechs();
		if (mechs != null) {
			for (int i = 0; i < mechs.length; i++) {
				System.out.println(mechs[i].toString());
			}
		}

		// release system resources held by the credential
		cred.dispose();

	}
}
