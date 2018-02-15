import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.URL;

import sun.net.www.protocol.http.HttpURLConnection;

public class RunHttpSpnego {

	static final String kuser = "login"; // your account name
	static final String kpass = "password"; // your password for the account

	static class MyAuthenticator extends Authenticator {
		@Override
		public PasswordAuthentication getPasswordAuthentication() {
			// I haven't checked getRequestingScheme() here, since for NTLM
			// and Negotiate, the usrname and password are all the same.
			System.err.println("Feeding username and password for " + this.getRequestingScheme());
			return (new PasswordAuthentication(kuser, kpass.toCharArray()));
		}
	}

	public static void main(final String[] args) throws Exception {

		System.setProperty("sun.security.krb5.debug", "true");
		System.setProperty("java.security.krb5.conf", "/etc/krb5.conf");
		System.setProperty("java.security.auth.login.config", "/home/nta/views/local/JAAS/1_gss_kerb/src/main/resources/login.conf");
		System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");

		URL url = new URL(args[0]);
		InputStream ins = null;
		Proxy proxy = null;
		BufferedReader reader = null;
		String str = null;
		Authenticator.setDefault(new MyAuthenticator());

		//		System.setProperty("http.proxyPort", "8080");
		//		System.setProperty("http.proxyHost", "winwebfilter01.ad.si2m.tec");
		//		ins = url.openConnection().getInputStream();

		// les 2 lignes suivantes equivalent aux 3 precedentes.
		proxy = new Proxy(Type.HTTP, new InetSocketAddress("winwebfilter01.ad.si2m.tec", 8080));
		HttpURLConnection cnx =  (HttpURLConnection) url.openConnection(proxy);
		ins = cnx.getInputStream();

		reader = new BufferedReader(new InputStreamReader(ins));
		while((str = reader.readLine()) != null) {
			System.out.println(str);
		}
	}
}