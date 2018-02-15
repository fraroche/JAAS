package fr.nta.security.http.spnego;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import sun.security.jgss.GSSHeader;
import sun.security.jgss.GSSManagerImpl;
import sun.security.jgss.spi.GSSContextSpi;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;
import sun.security.util.ObjectIdentifier;

import com.sun.security.jgss.GSSUtil;

import fr.nta.security.http.HttpAuthorizationDecorator;
import fr.nta.security.http.HttpAuthorizationException;
import fr.nta.security.http.IHttpAuthorizationChainComponant;
import fr.nta.security.jgss.spnego.SpnegoManager;

public class SpnegoAuthenticator extends HttpAuthorizationDecorator {

	private final static String NEGOTIATE = "Negotiate ";
	private final static Log	log	= LogFactory.getLog(SpnegoAuthenticator.class);

	public SpnegoAuthenticator(final IHttpAuthorizationChainComponant nextSecurityFilter) {
		super(nextSecurityFilter);
	}
	
	public void doProcess(final HttpServletRequest hreq, final HttpServletResponse hres) throws HttpAuthorizationException {
		final String header = hreq.getHeader("Authorization");
		
		if (log.isDebugEnabled()) {
			log.debug("Authorization: " + header);
		}
		
		if (isNegoTokenPresent(header)) {
			
//			GSSManager gssManager = null;
			GSSContext context = null;
			final byte[] token = Base64.decodeBase64(header.substring(NEGOTIATE.length()).getBytes());
			String responseToken = null;
			
//			Security.addProvider(SpNegoProvider.INSTANCE);
//			SpNegoProvider.seeProviderList();
//			token = Asn1Der.getInnerToken(token);
//System.out.println(this.getClass().getName()+" - "+ new String(token));
//			gssManager = GSSManager.getInstance();
			gssManager = SpnegoManager.getInstance();
			
			try {
//				context = gssManager.createContext(token);
				context = getContext(token);
				
//				logContext(context);
//				token = acceptSecContext(token, 0, token.length);
//				token = context.acceptSecContext(token, 0, token.length);
//				responseToken = new String(Base64.encodeBase64(token));
				responseToken = getToken(token, context);
				
				logContext(context);
				
				if (context.isEstablished()) {
					if (log.isDebugEnabled()) {
						log.debug("Context Established! ");
						log.debug("Client is " + context.getSrcName());
						log.debug("Server is " + context.getTargName());
					}
					final GSSName clientGSSName = context.getSrcName();
					final Subject client = GSSUtil.createSubject(clientGSSName, null);
					hres.setStatus(HttpServletResponse.SC_OK);
					hres.setHeader("WWW-Authenticate", NEGOTIATE + responseToken);
					nextComponant.doProcess(hreq, hres);
				} else {
					hres.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
					hres.setHeader("WWW-Authenticate", header);
				}
			} catch (final GSSException e) {
				e.printStackTrace();
				hres.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				hres.setHeader("WWW-Authenticate", header);
			} catch (final SecurityException e) {
				e.printStackTrace();
			}
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Server-Client Authentication request: " + "WWW-Authenticate - Negotiate");
			}
			hres.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			hres.setHeader("WWW-Authenticate", "Negotiate");
		}
	}
	
	private boolean isNegoTokenPresent(final String header) {
		return (header != null) && header.startsWith(NEGOTIATE) && (header.length() > NEGOTIATE.length());
	}
	
	private GSSContext getContext(final byte in[]) throws GSSException {
		GSSManager manager;
		if (in == null) {
			throw new GSSException(GSSException.NO_CONTEXT);
		}
		manager = SpnegoManager.getInstance();
		return manager.createContext(in);
	}
	
	private String getToken(final byte in[], final GSSContext context) throws GSSException {
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
	
	protected void logContext(final GSSContext context) {
		try {
			log.debug("Remaining lifetime in seconds = " + context.getLifetime());
			log.debug("Context mechanism = " + context.getMech());
			log.debug("Initiator = " + context.getSrcName());
			log.debug("Acceptor = " + context.getTargName());
			log.debug("isEstablished = " + context.isEstablished());
			
			if (context.getConfState()) {
				log.debug("Confidentiality (i.e., privacy) is available");
			}

			if (context.getIntegState()) {
				log.debug("Integrity is available");
			}
		} catch (final GSSException e) {
			e.printStackTrace();
		}
	}
	
	GSSManager gssManager = null;
    private byte[] acceptSecContext(final byte abyte0[], final int i, final int j) throws GSSException {
		final ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream(100);
		acceptSecContext(((new ByteArrayInputStream(abyte0, i, j))), ((bytearrayoutputstream)));
		return bytearrayoutputstream.toByteArray();
	}
    private void acceptSecContext(final InputStream inputstream, final OutputStream outputstream) throws GSSException {
    	int currentState = 2;
    	GSSContextSpi mechCtxt = null;
    	GSSCredential myCred = null;
    	GSSName srcName = null;
    	GSSName targName = null;
    	Oid mechOid = null;
    	ObjectIdentifier objId = null;
    	final ChannelBinding channelBindings = null;
    	
		if ((mechCtxt != null) && (currentState != 2)){
			return;
		}
		final Object obj = null;
		final boolean flag = false;
		try {
			final GSSHeader gssheader = new GSSHeader(inputstream);
			if (mechCtxt == null) {
				objId = gssheader.getOid();
				mechOid = new Oid(objId.toString());
				if (myCred == null) {
					myCred = gssManager.createCredential(null, 2147483647, mechOid, 2);
				}
				targName = myCred.getName();
				GSSCredentialSpi gsscredentialspi = null;
				try {
					final Class[] paramsType = {Oid.class, Boolean.TYPE};
					final Object[] params = {mechOid, Boolean.FALSE};
					gsscredentialspi = (GSSCredentialSpi) methodCall(myCred, "getElement", paramsType, params);
				} catch (final SecurityException e) {
					e.printStackTrace();
				} catch (final IllegalArgumentException e) {
					e.printStackTrace();
				} catch (final NoSuchMethodException e) {
					e.printStackTrace();
				} catch (final IllegalAccessException e) {
					e.printStackTrace();
				} catch (final InvocationTargetException e) {
					e.printStackTrace();
				}
				try {
					final Class[] paramsType = {GSSCredentialSpi.class, Oid.class};
					final Object[] params = {gsscredentialspi, mechOid};
					mechCtxt = (GSSContextSpi) methodCall(gssManager, "getMechanismContext", paramsType, params);
				} catch (final SecurityException e) {
					e.printStackTrace();
				} catch (final IllegalArgumentException e) {
					e.printStackTrace();
				} catch (final NoSuchMethodException e) {
					e.printStackTrace();
				} catch (final IllegalAccessException e) {
					e.printStackTrace();
				} catch (final InvocationTargetException e) {
					e.printStackTrace();
				}
//				GSSCredentialSpi gsscredentialspi = myCred.getElement(mechOid, false);
//				mechCtxt = gssManager.getMechanismContext(gsscredentialspi, mechOid);
				mechCtxt.setChannelBinding(channelBindings);
				currentState = 2;
			} else if (!gssheader.getOid().equals(objId)) {
				return;
			}
			final int i = gssheader.getMechTokenLength();
			final byte abyte0[] = mechCtxt.acceptSecContext(inputstream, i);
			if (abyte0 != null) {
				int j = abyte0.length;
				final GSSHeader gssheader1 = new GSSHeader(objId, abyte0.length);
				j += gssheader1.encode(outputstream);
				outputstream.write(abyte0);
			}
			try {
				final Class classType = Class.forName("sun.security.jgss.GSSNameImpl");
				final Class[] paramsType = {GSSManagerImpl.class, GSSNameSpi.class};
				final Object[] params = {gssManager, mechCtxt.getSrcName()};
				srcName = (GSSName) newObj(classType, paramsType, params);
			} catch (final SecurityException e) {
				e.printStackTrace();
			} catch (final IllegalArgumentException e) {
				e.printStackTrace();
			} catch (final NoSuchMethodException e) {
				e.printStackTrace();
			} catch (final InstantiationException e) {
				e.printStackTrace();
			} catch (final IllegalAccessException e) {
				e.printStackTrace();
			} catch (final InvocationTargetException e) {
				e.printStackTrace();
			} catch (final ClassNotFoundException e) {
				e.printStackTrace();
			}
//			srcName = new GSSNameImpl(gssManager, mechCtxt.getSrcName());
			if (mechCtxt.isEstablished()) {
				currentState = 3;
			}
		} catch (final IOException ioexception) {
//			throw new GSSExceptionImpl(10, ioexception.getMessage());
		}
	}
    private static Object newObj(final Class pClassType, final Class[] pParamsType, final Object[] pParams) throws SecurityException, NoSuchMethodException, IllegalArgumentException, InstantiationException, IllegalAccessException, InvocationTargetException {
		final Constructor initClassType = pClassType.getDeclaredConstructor(pParamsType);
		initClassType.setAccessible(true);
		return initClassType.newInstance(pParams);
    }
	private static Object methodCall(final Object pObject, final String pMethodName, final Class[] pParamsType, final Object[] pParams) throws NoSuchMethodException, SecurityException, IllegalAccessException,
			IllegalArgumentException, InvocationTargetException {
		final Class aClass = pObject.getClass();
		final Method aMethod = aClass.getDeclaredMethod(pMethodName, pParamsType);
		aMethod.setAccessible(true);
		final Object aReturnedObject = aMethod.invoke(pObject, pParams);
		return aReturnedObject;
	}
    
}
