
public class SecurityAssociations {
	/*
	private static class subject implements PrivilegedAction {
	    Principal principal;
	    Object credential;
	    Subject subject;
	
	    public Object run()
	    {
	        SecurityAssociation.pushSubjectContext(subject, principal, credential);
	        credential = null;
	        principal = null;
	        subject = null;
	        return null;
	    }
	
	    (Principal principal, Object credential, Subject subject)
	    {
	        this.principal = principal;
	        this.credential = credential;
	        this.subject = subject;
	    }
	}
	
	private static class SetPrincipalInfoAction implements PrivilegedAction {

		Principal	principal;
		Object		credential;
		Subject		subject;

		public Object run() {
			SecurityAssociation.pushSubjectContext(subject, principal, credential);
			credential = null;
			principal = null;
			subject = null;
			return null;
		}

		SetPrincipalInfoAction(final Principal principal, final Object credential, final Subject subject) {
			this.principal = principal;
			this.credential = credential;
			this.subject = subject;
		}
	}

	public SecurityAssociations() {
	}

	static void setPrincipalInfo(final Principal principal, final Object credential, final Subject subject) {
		final SetPrincipalInfoAction action = new SetPrincipalInfoAction(principal, credential, subject);
		AccessController.doPrivileged(action);
	}
	*/
}
