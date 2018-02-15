import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class GSSNameTest {
	public static void main(final String[] args) throws GSSException {
		final GSSManager manager = GSSManager.getInstance();

		// create a host based service name
		final GSSName name  = manager.createName("service@host", GSSName.NT_HOSTBASED_SERVICE);
		System.out.println(name.toString() +" "+ name.getStringNameType().toString());
		final Oid krb5 = new Oid("1.2.840.113554.1.2.2");

		final GSSName mechName = name.canonicalize(krb5);

		// the above two steps are equivalent to the following
//		final GSSName mechName = manager.createName("service@host", GSSName.NT_HOSTBASED_SERVICE, krb5);

		// perform name comparison
		if (name.equals(mechName)) {
			System.out.println("Names are equals.");
		}

		// obtain textual representation of name and its printable
		// name type
		System.out.println(mechName.toString() +" "+ mechName.getStringNameType().toString());
		System.out.println(name.toString() +" "+ name.getStringNameType().toString());

		// export and re-import the name
		final byte[] exportName = mechName.export();

		// create a new name object from the exported buffer
		final GSSName newName = manager.createName(exportName, GSSName.NT_EXPORT_NAME);

	}
}
