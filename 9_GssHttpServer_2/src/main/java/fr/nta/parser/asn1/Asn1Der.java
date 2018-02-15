package fr.nta.parser.asn1;

import java.io.IOException;
import java.io.StringReader;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public class Asn1Der {
	public static byte[] getInnerToken(final byte[] spnegoTkn) {
		
//		try {
//			final FileWriter fw = new java.io.FileWriter("C:/SPNEGO_Token");
//			fw.write(new String(spnegoTkn));
//			fw.flush();
//			fw.close();
//		} catch (final IOException e1) {
//			e1.printStackTrace();
//		}
//
		
//		int i = 0;
//		int j = 0;
//
//		if (0x60 != int2byte(spnegoTkn[i++])) {
//			System.out.println("structure should starts with 0x60");
//		}
//
//		i = endSizeTagIndex(spnegoTkn, i);
//
//		if (0x06 != int2byte(spnegoTkn[i++])) { // Spnego OID tag
//			System.out.println("structure should starts with 0x06");
//		}
//
//		j = endSizeTagIndex(spnegoTkn, i);
//		int sizeTagLength = j-i;
//		int structSize = getStructSize(spnegoTkn, i, sizeTagLength);
//		Oid oid;
//		try {
//			oid = getOid(spnegoTkn, i-1, sizeTagLength, structSize);
//		} catch (final GSSException e) {
//			e.printStackTrace();
//		}
//		i = i+sizeTagLength+structSize;
//
//		if (0xA0 != int2byte(spnegoTkn[i++])) {
//			System.out.println("structure should starts with 0xA0");
//		}
//
//		i = endSizeTagIndex(spnegoTkn, i);
//
//		if (0x30 != int2byte(spnegoTkn[i++])) {
//			System.out.println("structure should starts with 0x30");
//		}
//
//		i = endSizeTagIndex(spnegoTkn, i);
//
//		if (0xA0 != int2byte(spnegoTkn[i++])) {
//			System.out.println("structure should starts with 0xA0");
//		}
//
//		i = endSizeTagIndex(spnegoTkn, i);
//
//		if (0x30 != int2byte(spnegoTkn[i++])) {
//			System.out.println("structure should starts with 0x30");
//		}
//
//		i = endSizeTagIndex(spnegoTkn, i);
//
//		boolean isMechTypeListEmpty = true;
//		while (0x06 == int2byte(spnegoTkn[i++])) {
//			j = endSizeTagIndex(spnegoTkn, i);
//			sizeTagLength = j-i;
//			structSize = getStructSize(spnegoTkn, i, sizeTagLength);
//			try {
//				oid = getOid(spnegoTkn, i-1, sizeTagLength, structSize);
//			} catch (final GSSException e) {
//				e.printStackTrace();
//			}
//			i = i+sizeTagLength+structSize;
//			isMechTypeListEmpty = false;
//		}
//		if (isMechTypeListEmpty) {
//			System.out.println("structure should starts with 0x06");
//		}
//		i--;
//
//		if (0xA2 != int2byte(spnegoTkn[i++])) {
//			System.out.println("structure should starts with 0xA2");
//		}
//
//		i = endSizeTagIndex(spnegoTkn, i);
//
//		if (0x04 != int2byte(spnegoTkn[i++])) {
//			System.out.println("structure should starts with 0x04");
//		}
//
//		i = endSizeTagIndex(spnegoTkn, i);
//
//		if (0x60 != int2byte(spnegoTkn[i++])) {
//			System.out.println("structure should starts with 0x60");
//		}
//
//		j = endSizeTagIndex(spnegoTkn, i);
//		sizeTagLength = j-i;
//		structSize = getStructSize(spnegoTkn, i, sizeTagLength);
//		final byte[] krb5Tkn = getStructure(spnegoTkn, i-1, sizeTagLength, structSize);
//		i = i+sizeTagLength+structSize;
//
//		return krb5Tkn;
		
		byte[] krbTkn = null;
		try {
			final ASN1InputStream spnegoStream = new ASN1InputStream(spnegoTkn);
			final DERApplicationSpecific spnegoEnvelop = (DERApplicationSpecific) spnegoStream.readObject();
			final ASN1InputStream envelopContentStructure = new ASN1InputStream(spnegoEnvelop.getContents());
			final DERObjectIdentifier derSpnegoOID = (DERObjectIdentifier) envelopContentStructure.readObject();
			final DERTaggedObject envelopContent = (DERTaggedObject) envelopContentStructure.readObject();
			final DERSequence derseq = (DERSequence) envelopContent.getObject();
			final DERTaggedObject supportedProtocolsOidsTaggedObj = (DERTaggedObject) derseq.getObjectAt(0);
			final DERTaggedObject krbTokenTaggedObj = (DERTaggedObject) derseq.getObjectAt(1);
			final DEROctetString krbTokenOctetString = (DEROctetString) krbTokenTaggedObj.getObject();
			krbTkn = krbTokenOctetString.getOctets();
//			final ASN1InputStream krbStream = new ASN1InputStream(krbTkn);
//			final DERApplicationSpecific krbEnvelop = (DERApplicationSpecific) krbStream.readObject();
//			final ASN1InputStream envelopKrbContentStructure = new ASN1InputStream(krbEnvelop.getContents());
//			final DERObjectIdentifier derKrbOID = (DERObjectIdentifier) envelopKrbContentStructure.readObject();
		} catch (final IOException e) {
			e.printStackTrace();
		}
		return krbTkn;
	}

	private static Oid getOid(final byte[] tkn, final int oidStrtIndex, final int sizeTagLength, final int oidSize) throws GSSException {
		return new Oid(getStructure(tkn, oidStrtIndex, sizeTagLength, oidSize));
	}
	
	private static byte[] getStructure(final byte[] tkn, final int structStrtIndex, final int sizeTagLength, final int structSize) {
		final int structLength = 1+sizeTagLength+structSize;
		final byte[] struct = new byte[structLength];
		for (int k = structLength; k > 0; k--) {
			struct[structLength-k] = tkn[structStrtIndex+structLength-k];
		}
		return struct;
	}
	
	private static int getStructSize(final byte[] tkn, int index, int sizeTagLength) {
		int structSize=0;
		if (sizeTagLength > 1) {
			index++;
			sizeTagLength--;
		}
		for (int k = sizeTagLength; k > 0; k--) {
			final int octet = int2byte(tkn[index+sizeTagLength-k]);
			structSize = structSize | octet << (k-1)*8;
		}
		return structSize;
	}

	private static int endSizeTagIndex(final byte[] tkn, int index) {
		int size = tkn[index++];
		size = int2byte(size);
		if (size < 127) {
			
		} else {
			final int trap = 0x0000007F; //00000000000000000000000001111111
			size = trap & size;
			index+=size;
		}
		return index;
	}

	private static int int2byte(int octet) {
		final int trap = 0x000000FF; //00000000000000000000000011111111 -> int2byte
		octet = trap & octet;
		return octet;
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
	
	private static void pBinInt(final String s, final int i) {
		System.out.println(s + ", int: " + i + ", binary: ");
		System.out.print("   ");
		for (int j = 31; j >= 0; j--) {
			if (((1 << j) & i) != 0) {
				System.out.print("1");
			} else {
				System.out.print("0");
			}
		}
		System.out.println();
	}
	
	
	public static void main(final String[] args) throws IOException, GSSException {
		pBinInt("-96", -96);
		final String spnegoToken = "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";
		byte[] spnegoTkn = string2byte(spnegoToken);
		spnegoTkn = Base64.decodeBase64(spnegoTkn);
		final byte[] krb5Tkn = Asn1Der.getInnerToken(spnegoTkn);
		System.out.println("krb5Token = '"+byte2string(Base64.encodeBase64(krb5Tkn))+"'");
		System.out.println();
	}
}
