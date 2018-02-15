package fr.nta.security.gss;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

public abstract class GssClient {
	private boolean			mutualAuth	= true; // Mutual authentication
	private boolean			conf		= true; // Will use confidentiality later
	private boolean			replayDet	= true;
	private boolean			sequenceDet	= true;
	private boolean			integrity	= true; // Will use integrity later

	protected byte[]		inToken;
	protected GSSContext	context;
	protected GSSName		name;

	public GssClient(final boolean mutualAuth, final boolean conf, final boolean replayDet, final boolean sequenceDet, final boolean integrity) {
		this.conf = conf;
		this.mutualAuth = mutualAuth;
		this.replayDet = replayDet;
		this.sequenceDet = sequenceDet;
		this.integrity = integrity;
	}

	public GssClient() {
	}

	public final void establish() throws GSSException {
		final GSSContext context = computeContext();

		// set desired context options prior to context establishment
		context.requestConf(conf);
		context.requestMutualAuth(mutualAuth);
		context.requestReplayDet(replayDet);
		context.requestSequenceDet(sequenceDet);
		context.requestInteg(integrity);
		// establish a context between peers

		inToken = new byte[0];

		// Loop while there still is a token to be processed

		while (!context.isEstablished()) {

			final byte[] outToken = context.initSecContext(inToken, 0, inToken.length);
			logContext(context);
			
			// send the output token if generated
			if (outToken != null) {
				sendToken(outToken);
			}

			if (!context.isEstablished()) {
				inToken = readToken();
			}
		}
		// display context information
		System.out.println("Remaining lifetime in seconds = " + context.getLifetime());
		System.out.println("Context mechanism = " + context.getMech());
		System.out.println("Initiator = " + context.getSrcName());
		System.out.println("Acceptor = " + context.getTargName());

		if (context.getConfState()) {
			System.out.println("Confidentiality (i.e., privacy) is available");
		}

		if (context.getIntegState()) {
			System.out.println("Integrity is available");
		}

	}

	protected abstract GSSContext computeContext() throws GSSException;

	protected abstract void sendToken(final byte[] outToken);

	protected abstract byte[] readToken();
	
	protected abstract void logContext(final GSSContext context);
}
