

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class GssHttpClient extends DefaultHttpClient {
/*
	public static void main(final String[] args) throws Exception {
		final URL service = new URL("http://cmxd5014.dev.cm.par.emea.cib:10500/ImeWeb/index_auth.jsp");
		byte[] token = new byte[0];
		final DefaultHttpClient httpclient = new DefaultHttpClient();

		final HttpGet httpget = new HttpGet(service.toString());

		System.out.println("executing request" + httpget.getRequestLine());
		HttpResponse response = httpclient.execute(httpget);
		HttpEntity entity = response.getEntity();

		System.out.println("----------------------------------------");
		System.out.println(response.getStatusLine());
		if (entity != null) {
			System.out.println("Response content length: " + entity.getContentLength());
		}
		if (entity != null) {
			entity.consumeContent();
		}
		
		final GSSContext context = getContext(service);
		logContextStatus(context);
		token = context.initSecContext(token, 0, token.length);
		token = Base64.encodeBase64(token);
		System.out.println("TOKEN: " + byte2string(token));
		logContextStatus(context);
		
		httpget.addHeader(new BasicHeader("Authorization", "Negotiate " + byte2string(token)));
		System.out.println("executing request" + httpget.getRequestLine());
		response = httpclient.execute(httpget);
		entity = response.getEntity();

		System.out.println("----------------------------------------");
		System.out.println(response.getStatusLine());
		if (entity != null) {
			System.out.println("Response content length: " + entity.getContentLength());
		}
		if (entity != null) {
			entity.consumeContent();
		}
		
		httpclient.getConnectionManager().shutdown();
	}
*/
	
//	private String spn = null;
	private String spn = "HTTP/cmxd5014.dev.cm.par.emea.cib@CM.PAR.EMEA.CIB";

	public static void main(final String[] args) throws Exception {
//		final URL service = new URL("http://cmxd5014.dev.cm.par.emea.cib:10500/ImeWeb/index_auth.jsp");
		final URL service = new URL("http://cmxd5014.dev.cm.par.emea.cib:8080/GssHttpServerWeb/blaba");
		final GssHttpClient gssHttpClient = new GssHttpClient();
		
		byte[] inToken = new byte[0];

		HttpGet httpget = new HttpGet(service.toString());

		HttpResponse response = gssHttpClient.execute(httpget);
		HttpEntity entity = response.getEntity();
		if (entity != null) {
			entity.consumeContent();
		}
		
		System.out.println("executing request: " + httpget.getRequestLine());
		System.out.println(response.getStatusLine());
		System.out.println("----------------------------------------------");
		
		final GSSContext context = gssHttpClient.getContext(service);
		System.out.println("SPN: " + gssHttpClient.spn);
		logContextStatus(context);
		
		while(!context.isEstablished()) {
			System.out.println("----------------------------------------");
			System.out.println("----------------------------------------");
			
			byte[] outToken = context.initSecContext(inToken, 0, inToken.length);
			
			// send the output token if generated
			if (outToken != null) {
				outToken = Base64.encodeBase64(outToken);
				httpget = new HttpGet(service.toString());
				httpget.addHeader(new BasicHeader("Authorization", "Negotiate " + byte2string(outToken)));
				response = gssHttpClient.execute(httpget);
				entity = response.getEntity();
				if (entity != null) {
//					entity.consumeContent();
					
					final InputStream is = entity.getContent();
					final OutputStream os = System.out;
					try {
						for (int i=is.read(); i!=-1; i=is.read()) {
							os.write(i);
						}
					} finally {
						os.flush();
						os.close();
						is.close();
					}
				}
			}
			//---------------------------------------

			System.out.println("OUT TOKEN: " + byte2string(outToken));
			
			// read token
			if (!context.isEstablished()) {
				final Header authenticate = response.getFirstHeader("WWW-Authenticate");
				String stringToken = authenticate.getValue();
				stringToken = stringToken.substring(10);
				inToken = string2byte(stringToken);
				System.out.println("IN TOKEN:  " + byte2string(inToken));
				inToken = Base64.decodeBase64(inToken);
			}
			
			System.out.println("executing request" + httpget.getRequestLine());
			System.out.println(response.getStatusLine());
			System.out.println("----------------------------------------------");
			logContextStatus(context);
		}
		
		gssHttpClient.getConnectionManager().shutdown();
	}

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	public static String byte2string(final byte[] in) {
		if (in == null) {
			return "";
		}
		return new String(in);
	}
	
	public static byte[] string2byte(final String in) throws IOException {
		final byte[] out = new byte[in.length()];
		final StringReader readInt = new StringReader(in);
		for (int i = readInt.read(), j = 0; i != -1; i = readInt.read(), j++) {
			out[j] = (byte) i;
		}
		return out;
	}
	
	public static byte[] string2key(final String pwd, final String salt) throws NoSuchAlgorithmException, IOException {
		final MessageDigest digest = MessageDigest.getInstance("MD5");
		final String in = pwd + salt;
		byte[] hash = null;
		digest.update(string2byte(in));
		hash = digest.digest();
		return hash;
	}
	
	public static void logContextStatus(final GSSContext context) {
		try {
			System.out.println("Remaining lifetime in seconds = " + context.getLifetime());
			System.out.println("Context mechanism = " + context.getMech());
			System.out.println("Initiator = " + context.getSrcName());
			System.out.println("Acceptor = " + context.getTargName());
			System.out.println("isEstablished = " + context.isEstablished());

			if (context.getConfState()) {
				System.out.println("Confidentiality (i.e., privacy) is available");
			}

			if (context.getIntegState()) {
				System.out.println("Integrity is available");
			}
		} catch (final GSSException e) {
			e.printStackTrace();
		}
	}

	public GSSContext getContext(final URL service) throws GSSException {
		final String protocol = service.getProtocol();
		final String host = service.getHost();
		// final String spn = protocol.toUpperCase() + "/" + host.substring(0,
		// host.indexOf(".")) + "@" +
		// host.substring(host.indexOf(".")+1).toUpperCase();
		if (this.spn == null) {
			this.spn = protocol + "/" + host + "@" + host.substring(host.indexOf("dev.") + 4).toUpperCase();
		}
		final Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");
		final GSSManager manager = GSSManager.getInstance();
		final GSSName serverName = manager.createName(spn, null);
		final GSSContext context = manager.createContext(serverName, krb5Oid, null, GSSContext.DEFAULT_LIFETIME);
		context.requestMutualAuth(true); // Mutual authentication
		// context.requestConf(true); // Will use confidentiality later
		// context.requestInteg(true); // Will use integrity later
		return context;
	}
}
