

import java.net.URL;

import javax.security.auth.Subject;
import javax.security.auth.login.AccountExpiredException;
import javax.security.auth.login.CredentialExpiredException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import com.sun.security.auth.callback.TextCallbackHandler;

/**
 * <p>
 * This class authenticates a <code>Subject</code> and then executes a
 * specified application as that <code>Subject</code>. To use this class, the
 * java interpreter would typically be invoked as:
 * 
 * <pre>
 *    % java -Djava.security.manager \
 *        Login \
 *        &lt;applicationclass&gt; &lt;applicationClass_args&gt;
 * </pre>
 * 
 * <p>
 * <i>applicationClass</i> represents the application to be executed as the
 * authenticated <code>Subject</code>, and <i>applicationClass_args</i> are
 * passed as arguments to <i>applicationClass</i>.
 * 
 * <p>
 * To perform the authentication, <code>Login</code> uses a
 * <code>LoginContext</code>. A <code>LoginContext</code> relies on a
 * <code>Configuration</code> to determine the modules that should be used to
 * perform the actual authentication. The location of the Configuration is
 * dependent upon each Configuration implementation. The default Configuration
 * implementation (<code>com.sun.security.auth.login.ConfigFile</code>)
 * allows the Configuration location to be specified (among other ways) via the
 * <code>java.security.auth.login.config</code> system property. Therefore,
 * the <code>Login</code> class can also be invoked as:
 * 
 * <pre>
 *    % java -Djava.security.manager \
 *        -Djava.security.auth.login.config=&lt;configuration_url&gt; \
 *        Login \
 *        &lt;your_application_class&gt; &lt;your_application_class_args&gt;
 * </pre>
 */

public class Login {

	/**
	 * <p>
	 * Instantate a <code>LoginContext</code> using the provided application
	 * classname as the index for the sample <code>Configuration</code>.
	 * Authenticate the <code>Subject</code> (three retries are allowed) and
	 * invoke <code>Subject.doAsPrivileged</code> with the authenticated
	 * <code>Subject</code> and a <code>PrivilegedExceptionAction</code>.
	 * The <code>PrivilegedExceptionAction</code> loads the provided
	 * application class, and then invokes its public static <code>main</code>
	 * method, passing it the application arguments.
	 * 
	 * <p>
	 * 
	 * @param args
	 *            the arguments for <code>Login</code>. The first argument
	 *            must be the class name of the application to be invoked once
	 *            authentication has completed, and the subsequent arguments are
	 *            the arguments to be passed to that application's public static
	 *            <code>main</code> method.
	 */
	public static void main(final String[] args) {

		for (String lString : args) {
			System.out.println(lString);
		}

		System.out.println("Login.main() - 1");

		// check for the application's main class
		if ((args == null) || (args.length == 0)) {
			System.err.println("Invalid arguments: " + "Did not provide name of application class.");
			System.exit(-1);
		}

		System.out.println("Login.main() - 2");

		LoginContext lc = null;
		try {
			URL a = Thread.currentThread().getContextClassLoader().getResource("/");
			URL b = Thread.currentThread().getContextClassLoader().getResource("sample.conf");
			URL c = Thread.currentThread().getContextClassLoader().getResource("/sample.conf");
			lc = new LoginContext(args[0], new TextCallbackHandler());
			System.out.println("Login.main() - 3");

		} catch (final LoginException le) {
			System.err.println("Cannot create LoginContext. " + le.getMessage());
			System.exit(-1);
		} catch (final SecurityException se) {
			System.err.println("Cannot create LoginContext. " + se.getMessage());
			System.exit(-1);
		}

		// the user has 3 attempts to authenticate successfully
		int i;
		for (i = 0; i < 3; i++) {
			try {

				System.out.println("Login.main() - 4");

				// attempt authentication
				lc.login();


				System.out.println("Login.main() - 5");
				// if we return with no exception, authentication succeeded
				break;

			} catch (final AccountExpiredException aee) {

				System.err.println("Your account has expired.  " + "Please notify your administrator.");
				System.exit(-1);

			} catch (final CredentialExpiredException cee) {

				System.err.println("Your credentials have expired.");
				System.exit(-1);

			} catch (final FailedLoginException fle) {

				System.err.println("Authentication Failed");
				try {
					Thread.sleep(3000);
				} catch (final Exception e) {
					// ignore
				}

			} catch (final Exception e) {

				System.err.println("Unexpected Exception - unable to continue");
				e.printStackTrace();
				System.exit(-1);
			}
		}

		// did they fail three times?
		if (i == 3) {
			System.err.println("Sorry");
			System.exit(-1);
		}

		// push the subject into the current ACC
		try {

			System.out.println("Login.main() - 6");

			Subject.doAsPrivileged(lc.getSubject(), new MyAction(args), null);
		} catch (final java.security.PrivilegedActionException pae) {
			pae.printStackTrace();
			System.exit(-1);
		}

		System.exit(0);
	}
}

class MyAction implements java.security.PrivilegedExceptionAction {

	String[]	origArgs;

	public MyAction(final String[] origArgs) {
		this.origArgs = origArgs.clone();
	}

	public Object run() throws Exception {

		// get the ContextClassLoader
		final ClassLoader cl = Thread.currentThread().getContextClassLoader();

		try {
			// get the application class's main method
			final Class c = Class.forName(this.origArgs[1], true, cl);
			final Class[] PARAMS = { this.origArgs.getClass() };
			final java.lang.reflect.Method mainMethod = c.getMethod("main", PARAMS);

			// invoke the main method with the remaining args
			final String[] appArgs = new String[this.origArgs.length - 1];
			System.arraycopy(this.origArgs, 1, appArgs, 0, this.origArgs.length - 1);
			final Object[] args = { appArgs };
			mainMethod.invoke(null /* ignored */, args);
		} catch (final Exception e) {
			throw new java.security.PrivilegedActionException(e);
		}

		// successful completion
		return null;
	}
}
