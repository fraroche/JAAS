package sun.security.jgss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;

import fr.nta.parser.asn1.Asn1Der;
import fr.nta.security.jgss.spnego.SpNegoProvider;


public class SpnegoContext implements GSSContext {

	GSSContext gssContext = null;
	
	public SpnegoContext(final GSSContext gssContext) throws GSSException {
		this.gssContext = gssContext;
	}

	public byte[] acceptSecContext(final byte[] inToken, final int offset, final int length) throws GSSException {
		final ByteArrayOutputStream baos = new ByteArrayOutputStream(100);
		this.acceptSecContext(((new ByteArrayInputStream(inToken, offset, length))), ((baos)));
		return baos.toByteArray();
	}

	public void acceptSecContext(InputStream is, final OutputStream os) throws GSSException {
		try {
			byte[] inToken = null;
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			for(int i = is.read(); i != -1; baos.write(i), i = is.read());
			baos.flush();
			baos.close();
			is.close();
			inToken = baos.toByteArray();
			
			is = new ByteArrayInputStream(inToken, 0, inToken.length);
			final GSSHeader gssHeader = new GSSHeader(is);
			if (gssHeader.getOid().toString().equals(SpNegoProvider.SPNEGO_OID)) {
				inToken = Asn1Der.getInnerToken(inToken);
			}
			gssContext.acceptSecContext(inToken, 0, inToken.length);
			
		} catch (final IOException e) {
			e.printStackTrace();
		}
	}

	public void dispose() throws GSSException {
		gssContext.dispose();
	}

	public byte[] export() throws GSSException {
		return gssContext.export();
	}

	public boolean getAnonymityState() {
		return gssContext.getAnonymityState();
	}

	public boolean getConfState() {
		return gssContext.getConfState();
	}

	public boolean getCredDelegState() {
		return gssContext.getCredDelegState();
	}

	public GSSCredential getDelegCred() throws GSSException {
		return gssContext.getDelegCred();
	}

	public boolean getIntegState() {
		return gssContext.getIntegState();
	}

	public int getLifetime() {
		return gssContext.getLifetime();
	}

	public Oid getMech() throws GSSException {
		return gssContext.getMech();
	}

	public byte[] getMIC(final byte[] inMsg, final int offset, final int len, final MessageProp msgProp) throws GSSException {
		return gssContext.getMIC(inMsg, offset, len, msgProp);
	}

	public void getMIC(final InputStream inStream, final OutputStream outStream, final MessageProp msgProp) throws GSSException {
		gssContext.getMIC(inStream, outStream, msgProp);
	}

	public boolean getMutualAuthState() {
		return gssContext.getMutualAuthState();
	}

	public boolean getReplayDetState() {
		return gssContext.getReplayDetState();
	}

	public boolean getSequenceDetState() {
		return gssContext.getSequenceDetState();
	}

	public GSSName getSrcName() throws GSSException {
		return gssContext.getSrcName();
	}

	public GSSName getTargName() throws GSSException {
		return gssContext.getTargName();
	}

	public int getWrapSizeLimit(final int qop, final boolean confReq, final int maxTokenSize) throws GSSException {
		return gssContext.getWrapSizeLimit(qop, confReq, maxTokenSize);
	}

	public byte[] initSecContext(final byte[] inputBuf, final int offset, final int len) throws GSSException {
		return gssContext.initSecContext(inputBuf, offset, len);
	}

	public int initSecContext(final InputStream inStream, final OutputStream outStream) throws GSSException {
		return gssContext.initSecContext(inStream, outStream);
	}

	public boolean isEstablished() {
		return gssContext.isEstablished();
	}

	public boolean isInitiator() throws GSSException {
		return gssContext.isInitiator();
	}

	public boolean isProtReady() {
		return gssContext.isProtReady();
	}

	public boolean isTransferable() throws GSSException {
		return gssContext.isTransferable();
	}

	public void requestAnonymity(final boolean state) throws GSSException {
		gssContext.requestAnonymity(state);
	}

	public void requestConf(final boolean state) throws GSSException {
		gssContext.requestConf(state);
	}

	public void requestCredDeleg(final boolean state) throws GSSException {
		gssContext.requestCredDeleg(state);
	}

	public void requestInteg(final boolean state) throws GSSException {
		gssContext.requestInteg(state);
	}

	public void requestLifetime(final int lifetime) throws GSSException {
		gssContext.requestLifetime(lifetime);
	}

	public void requestMutualAuth(final boolean state) throws GSSException {
		gssContext.requestMutualAuth(state);
	}

	public void requestReplayDet(final boolean state) throws GSSException {
		gssContext.requestReplayDet(state);
	}

	public void requestSequenceDet(final boolean state) throws GSSException {
		gssContext.requestSequenceDet(state);
	}

	public void setChannelBinding(final ChannelBinding cb) throws GSSException {
		gssContext.setChannelBinding(cb);
	}

	public byte[] unwrap(final byte[] inBuf, final int offset, final int len, final MessageProp msgProp) throws GSSException {
		return gssContext.unwrap(inBuf, offset, len, msgProp);
	}

	public void unwrap(final InputStream inStream, final OutputStream outStream, final MessageProp msgProp) throws GSSException {
		gssContext.unwrap(inStream, outStream, msgProp);
	}

	public void verifyMIC(final byte[] inToken, final int tokOffset, final int tokLen, final byte[] inMsg, final int msgOffset, final int msgLen, final MessageProp msgProp) throws GSSException {
		gssContext.verifyMIC(inToken, tokOffset, tokLen, inMsg, msgOffset, msgLen, msgProp);
	}

	public void verifyMIC(final InputStream tokStream, final InputStream msgStream, final MessageProp msgProp) throws GSSException {
		gssContext.verifyMIC(tokStream, msgStream, msgProp);
	}

	public byte[] wrap(final byte[] inBuf, final int offset, final int len, final MessageProp msgProp) throws GSSException {
		return gssContext.wrap(inBuf, offset, len, msgProp);
	}

	public void wrap(final InputStream inStream, final OutputStream outStream, final MessageProp msgProp) throws GSSException {
		gssContext.wrap(inStream, outStream, msgProp);
	}
	
	
	
}
