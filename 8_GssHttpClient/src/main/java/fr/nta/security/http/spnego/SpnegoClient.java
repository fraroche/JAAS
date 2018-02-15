package fr.nta.security.http.spnego;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import fr.nta.security.gss.krb5.GssKrb5Client;


public class SpnegoClient extends GssKrb5Client {
	private static void createFile(final StringBuffer strBuff, final String filePath) {
		final File file = new File(filePath);
		FileWriter fw = null;
		try {
			fw = new FileWriter(file);
			if (strBuff != null) {
				fw.write(strBuff.toString());
			}
			fw.flush();
		} catch (final IOException ioe) {
			ioe.printStackTrace();
		}
	}
	public static void main(final String[] args) throws URISyntaxException, IOException {
		
		final String spnegoToken = "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";
		byte[] spnegoTkn = string2byte(spnegoToken);
		spnegoTkn = Base64.decodeBase64(spnegoTkn);
		createFile(new StringBuffer(byte2string(spnegoTkn)), "C:/SPNEGO_REQ");
		
		final String spnego5respToken = "oYGsMIGpoAMKAQChCwYJKoZIhvcSAQIComwEamBoBgkqhkiG9xIBAgICAG9ZMFegAwIBBaEDAgEPokswSaADAgEDokIEQGZ6XtAdDoUAi4rtc0vVRnXDBro9VOOVptlshAgo/q+wKPf7bQU5a5M7kRfGIUqbPd1Kel25qqmmvynf/H3vSM+jJwQlYCMGCSqGSIb3EgECAgEBAAD/////F8ElWEPMjzNSoOfqEkUNzw==";
		byte[] spnego5respTkn = string2byte(spnego5respToken);
		spnego5respTkn = Base64.decodeBase64(spnego5respTkn);
		createFile(new StringBuffer(byte2string(spnego5respTkn)), "C:/SPNEGO_RESP");
		
		final String krb5Token = "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";
		byte[] krb5Tkn = string2byte(krb5Token);
		krb5Tkn = Base64.decodeBase64(krb5Tkn);
		createFile(new StringBuffer(byte2string(krb5Tkn)), "C:/KRB5_REQ");
		
		final String krb5respToken = "YGgGCSqGSIb3EgECAgIAb1kwV6ADAgEFoQMCAQ+iSzBJoAMCAQOiQgRAhnhy+mzKVYw9QBd+6xXgjnsIKRL7u/rQfs6/YUnA570p4ApcwTcC7Q78lB5pnj4sPz82UANYlqv2uuD+ag6bIQ==";
		byte[] krb5respTkn = string2byte(krb5respToken);
		krb5respTkn = Base64.decodeBase64(krb5respTkn);
		createFile(new StringBuffer(byte2string(krb5respTkn)), "C:/KRB5_RESP");
		
		final URL service = new URL("http://cmxd5014.dev.cm.par.emea.cib:10500/ImeWeb/index_auth.jsp");
//		final URL service = new URL("http://cmxd5014.dev.cm.par.emea.cib:8080/GssHttpServerWeb/blaba");
		final String SPN = "HTTP/cmxd5014.dev.cm.par.emea.cib@CM.PAR.EMEA.CIB";
//		final String SPN = "ut11am@CM.PAR.EMEA.CIB";
		
		final SpnegoClient sc = new SpnegoClient(SPN, service);
		
	}
	
	private HttpResponse response;
	private final AbstractHttpClient httpClient;
	private final URL service;
	
	public SpnegoClient(final String SPN, final URL service) {
		super(SPN == null?computeSPN(service):SPN);
		this.service = service;
		this.httpClient = new DefaultHttpClient();
		
		try {
			final HttpGet httpget = new HttpGet(service.toString());
			this.response = httpClient.execute(httpget);
			final HttpEntity entity = this.response.getEntity();
			if (entity != null) {
				entity.consumeContent();
			}
			System.out.println("executing request" + httpget.getRequestLine());
			System.out.println(this.response.getStatusLine());
			System.out.println("----------------------------------------------");
			
			super.establish();
			
		} catch (final URISyntaxException e) {
			e.printStackTrace();
		} catch (final HttpException e) {
			e.printStackTrace();
		} catch (final IOException e) {
			e.printStackTrace();
		} catch (final GSSException e) {
			e.printStackTrace();
		}
	}

	protected byte[] readToken() {
		final Header authenticate = this.response.getFirstHeader("WWW-Authenticate");
		String stringToken = authenticate.getValue();
		stringToken = stringToken.substring(10);
		try {
			inToken = string2byte(stringToken);
		} catch (final IOException e) {
			e.printStackTrace();
		}
		System.out.println("IN TOKEN:  " + byte2string(inToken));
		return Base64.decodeBase64(inToken);
	}

	protected void sendToken(final byte[] token) {
		final byte[] outToken = Base64.encodeBase64(token);
		HttpGet httpget;
		try {
			httpget = new HttpGet(this.service.toString());
			final String strOutToken = byte2string(outToken);
			httpget.addHeader(new BasicHeader("Authorization", "Negotiate " + strOutToken));
			System.out.println("OUT TOKEN: " + byte2string(inToken));
			response = httpClient.execute(httpget);
			final HttpEntity entity = response.getEntity();
			if (entity != null) {
				entity.consumeContent();
			}
		} catch (final URISyntaxException e) {
			e.printStackTrace();
		} catch (final HttpException e) {
			e.printStackTrace();
		} catch (final IOException e) {
			e.printStackTrace();
		}
	}


	public GSSContext _computeContext() throws GSSException {
		final Oid krb5MechOid = new Oid("1.2.840.113554.1.2.2");
		final Oid krb5PrincipalNameType = new Oid("1.2.840.113554.1.2.2.1");
		final Oid spnegoMechOid  = new Oid("1.3.6.1.5.5.2");
		final Oid spnegoPrincipalNameType  = new Oid("1.3.6.1.5.5.2.1");
		System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
		final GSSManager manager = GSSManager.getInstance();
		final GSSCredential clientGssCreds = manager.createCredential(null,
                GSSCredential.INDEFINITE_LIFETIME,
                krb5MechOid, GSSCredential.INITIATE_ONLY);
		clientGssCreds.add(null,
                GSSCredential.INDEFINITE_LIFETIME,
                GSSCredential.INDEFINITE_LIFETIME,
                spnegoMechOid, GSSCredential.INITIATE_ONLY);
		// create target server SPN
		final GSSName gssServerName = manager.createName("HTTP/cmxd5014.dev.cm.par.emea.cib@CM.PAR.EMEA.CIB", krb5PrincipalNameType);
		System.out.println(gssServerName.toString()+" - "+gssServerName.getStringNameType());
//		gssServerName = gssServerName.canonicalize(spnegoMechOid);
//		System.out.println(gssServerName.toString()+" - "+gssServerName.getStringNameType());
		final GSSContext clientContext = manager.createContext(gssServerName, spnegoMechOid, clientGssCreds, GSSContext.DEFAULT_LIFETIME);
		return clientContext;
	}
	
	
	protected void logContext(final GSSContext context) {
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

	private static String computeSPN(final URL service) {
		final String protocol = service.getProtocol();
		final String host = service.getHost();
		final String spn = protocol + "/" + host + "@" + host.substring(host.indexOf("dev.") + 4).toUpperCase();
		return spn;
	}
	private static String byte2string(final byte[] in) {
		if (in == null) {
			return "";
		}
		return new String(in);
	}
	private static byte[] string2byte(final String in) throws IOException {
		final byte[] out = new byte[in.length()];
		final StringReader readInt = new StringReader(in);
		for (int i = readInt.read(), j = 0; i != -1; i = readInt.read(), j++) {
			out[j] = (byte) i;
		}
		return out;
	}
	private static byte[] string2key(final String pwd, final String salt) throws NoSuchAlgorithmException, IOException {
		final MessageDigest digest = MessageDigest.getInstance("MD5");
		final String in = pwd + salt;
		byte[] hash = null;
		digest.update(string2byte(in));
		hash = digest.digest();
		return hash;
	}
	
}
