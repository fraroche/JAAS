import java.security.Principal;
import org.ietf.jgss.GSSName;

public class SimpleGSSPrincipal implements Principal {

	private GSSName	gssName;

	public SimpleGSSPrincipal() {
	}

	public SimpleGSSPrincipal(final GSSName gssName) {
		this.gssName = gssName;
	}

	public GSSName getGssName() {
		return gssName;
	}

	public void setGssName(final GSSName gssName) {
		this.gssName = gssName;
	}

	public String getName() {
		return getGssName().toString();
	}
}
