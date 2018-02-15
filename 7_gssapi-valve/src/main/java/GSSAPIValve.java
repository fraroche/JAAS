import java.io.IOException;

import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;

//public class GSSAPIValve implements IGenericInterceptor {
//public class GSSAPIValve extends ValveBase {
public class GSSAPIValve {

	private static final Log	log	= LogFactory.getLog(GSSAPIValve.class);
	private String				overrideMech;

	public GSSAPIValve() {
		setOverrideMech("BASIC");
	}

	public String getOverrideMech() {
		return overrideMech;
	}

	public void setOverrideMech(final String overrideMech) {
		this.overrideMech = overrideMech.trim();
	}
	
	/**
	 * <tt>SPNEGO [RFC4178] / HTTP_1.1 [RFC2616]</tt> using <tt>GSS-API [RFC2743] / Kerberos [RFC4121]</tt> Implementation.<br>
	 * Protocol description (cf. [RFC4559]) :<br><br>
	 * 
	 *   The client requests an access-protected document from server via a
	 *   GET method request.  The URI of the document is<br>
	 *   <tt>"http://www.nowhere.org/dir/index.html"</tt>.<br><br>
	 *
	 *           <tt>C: GET dir/index.html</tt><br><br>
	 *
	 *   The first time the client requests the document, no Authorization
	 *   header is sent, so the server responds with<br><br>
	 *
	 *           <tt>S: HTTP/1.1 401 Unauthorized</tt><br>
	 *           <tt>S: WWW-Authenticate: Negotiate</tt><br><br>
	 *
	 *   The client will obtain the user credentials using the SPNEGO GSSAPI
	 *   mechanism type to identify generate a GSSAPI message to be sent to
	 *   the server with a new request, including the following Authorization
	 *   header:<br><br>
	 *
	 *           <tt>C: GET dir/index.html</tt><br>
	 *           <tt>C: Authorization: Negotiate a87421000492aa874209af8bc028</tt><br><br>
	 *
	 *   The server will decode the <tt>gssapi-data</tt> and pass this to the SPNEGO
	 *   GSSAPI mechanism in the <tt>gss_accept_security_context</tt> function.  If the
	 *   context is not complete, the server will respond with a 401 status
	 *   code with a <tt>WWW-Authenticate</tt> header containing the <tt>gssapi-data</tt>.<br><br>
	 *
	 *           <tt>S: HTTP/1.1 401 Unauthorized</tt><br>
	 *           <tt>S: WWW-Authenticate: Negotiate 749efa7b23409c20b92356</tt><br><br>
	 *
	 *   The client will decode the gssapi-data, pass this into
	 *   <tt>Gss_Init_security_context</tt>, and return the new <tt>gssapi-data</tt> to the
	 *   server.<br><br>
	 *
	 *           <tt>C: GET dir/index.html</tt><br>
	 *           <tt>C: Authorization: Negotiate 89a8742aa8729a8b028</tt><br><br>
	 *
	 *   This cycle can continue until the security context is complete.  When
	 *   the return value from the <tt>gss_accept_security_context</tt> function
	 *   indicates that the security context is complete, it may supply final
	 *   authentication data to be returned to the client.  If the server has
	 *   more gssapi data to send to the client to complete the context, it is
	 *   to be carried in a <tt>WWW-Authenticate</tt> header with the final response
	 *   containing the HTTP body.<br><br>
	 *
	 *           <tt>S: HTTP/1.1 200 Success</tt><br>
	 *           <tt>S: WWW-Authenticate: Negotiate ade0234568a4209af8bc0280289eca</tt><br><br>
	 *
	 *   The client will decode the gssapi-data and supply it to
	 *   <tt>gss_init_security_context</tt> using the context for this server.  If the
	 *   status is successful from the final <tt>gss_init_security_context</tt>, the
	 *   response can be used by the application.
	 */
	public void next(final Request request, final Response response) throws IOException, ServletException {
		final HttpServletRequest hreq = request.getRequest();
		final HttpServletResponse hres = response.getResponse();
		log.debug("GSSAPI valve entered");
		boolean headerPresent = false;
		final String header = hreq.getHeader("Authorization");
		log.debug("Authorization: " + header);
		if ((header != null) && header.startsWith("Negotiate ") && (header.length() > 10)) {
			log.debug("GSSAPI Authorization header found with " + (header.length() - 10) + " bytes");
			GSSContext gcontext = null;
			String outToken = null;
			try {
				final byte in[] = Base64.decodeBase64(header.substring(10).getBytes());
				gcontext = getContext(in);
				outToken = getToken(in, gcontext);
			} catch (final GSSException gsse) {
				throw new ServletException(gsse);
			}
			if (outToken != null) {
				hres.setHeader("WWW-Authenticate", "Negotiate " + outToken.getBytes());
			} else {
				hres.setHeader("WWW-Authenticate", "Negotiate");
			}
			headerPresent = true;
			if ((gcontext != null) && gcontext.isEstablished()) {
				try {
					final Subject subject = new Subject();
					final GSSName sname = gcontext.getSrcName();
					final java.security.Principal identity = new SimpleGSSPrincipal(sname);
					request.setUserPrincipal(identity);
					request.setAuthType("NEGOTIATE");
					subject.getPrincipals().add(identity);
					log.debug("Authorized name: " + sname);
					GSSCredential dc = null;
					if (gcontext.getCredDelegState()) {
						dc = gcontext.getDelegCred();
						final GSSName dname = dc.getName();
						subject.getPrincipals().add(new SimpleGSSPrincipal(dname));
						subject.getPrivateCredentials().add(gcontext.getDelegCred());
						log.debug("Delegated name: " + dname);
					}
//					SecurityAssociations.setPrincipalInfo(identity, dc, subject);
				} catch (final Exception ex) {
					log.info(ex);
					hres.addHeader("Client-Warning", ex.getMessage());
					hres.setStatus(401);
				}
			} else {
				hres.setStatus(401);
				log.debug("GSS-KERBEROS5: Unauthorized");
			}
		}
		
//		super.getNext().invoke(request, response);
		
		log.debug("GSSAPI valve ending");
		if ((response.getHeader("WWW-Authenticate") != null) && !headerPresent && response.getHeader("WWW-Authenticate").toUpperCase().startsWith(getOverrideMech().toUpperCase())) {
			log.debug("Replacing " + getOverrideMech() + " with Negotiate in WWW-Authenticate header");
			hres.setHeader("WWW-Authenticate", "Negotiate");
		}
	}
	
	protected GSSContext getContext(final byte in[]) throws GSSException {
		GSSManager manager;
		if (in == null) {
			throw new GSSException(GSSException.NO_CONTEXT);
		}
		manager = GSSManager.getInstance();
		return manager.createContext(in);
	}

	protected String getToken(final byte in[], final GSSContext context) throws GSSException {
		if ((in == null) || (context == null)) {
			final GSSException gsse = new GSSException(GSSException.NO_CONTEXT);
			log.error("GSSException: " + gsse.getMessage());
			log.error("GSSException major: " + gsse.getMajorString());
			log.error("GSSException minor: " + gsse.getMinorString());
			throw gsse;
		}
		final byte out[] = context.acceptSecContext(in, 0, in.length);
		return new String(Base64.encodeBase64(out));
	}

	static Class _mthclass$(final String x0) {
		try {
			return Class.forName(x0);
		} catch (final ClassNotFoundException x1) {
	        throw new NoClassDefFoundError(x1.getMessage());
		}
    }
}