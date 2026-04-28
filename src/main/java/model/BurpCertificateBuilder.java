package model;

import helpers.CertificateHelper;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class BurpCertificateBuilder {
	BurpCertificate burpCertificate;
	X509Certificate issuerCertificate;

	private int version;
	private BigInteger serial;
	private X500Principal issuer;
	private Date notBefore;
	private Date notAfter;
	private X500Principal subject;
	private String signatureAlgorithm;

	private List<GeneralName> issuerAlternativeName;
	private List<GeneralName> subjectAlternativeName;
	private Set<Integer> keyUsage;
	private Set<KeyPurposeId> extendedKeyUsage;
	private boolean hasBasicConstraints;
	private boolean isCA;
	private int pathLimit;
	private boolean hasNoPathLimit;
	private boolean setSubjectKeyIdentifier;
	private String authorityKeyIdentifier;
	private String subjectKeyIdentifier;

	private List<BurpCertificateExtension> burpCertificateExtensions;

	private int keySize;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private boolean setAuthorityKeyIdentifier;

	public BurpCertificateBuilder(String subject) {
		Security.addProvider(new BouncyCastleProvider());
		version = 3;
		serial = BigInteger.valueOf(System.currentTimeMillis());
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.DATE, -1);
		notBefore = calendar.getTime();
		calendar.add(Calendar.DATE, 366);
		notAfter = calendar.getTime();
		this.subject = new X500Principal(subject);
		signatureAlgorithm = "SHA256withRSA";
		keySize = 2048;
		issuer = this.subject;
		burpCertificateExtensions = new LinkedList<>();
		pathLimit = Integer.MAX_VALUE; // No limit
		keyUsage = new HashSet<>();
		extendedKeyUsage = new HashSet<>();
		subjectAlternativeName = new LinkedList<>();
		issuerAlternativeName = new LinkedList<>();
		authorityKeyIdentifier = "";
		subjectKeyIdentifier = "";
	}

	/**
	 * Generates a new certificate and sets the fields Private/Public Key and
	 * Source of this object. The certificate is signed with the private key of
	 * the given issuer.
	 *
	 * @param issuer
	 *            The Private Key of this issuer is used for signing
	 * @return New certificate object for our plugin
	 * @throws CertificateEncodingException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws InvalidKeySpecException
	 */
	public BurpCertificate generateCertificate(BurpCertificate issuer) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException,
			NoSuchProviderException, IOException, InvalidKeySpecException {
		if (privateKey == null || publicKey == null) {
			generateKeyPair();
		}
		burpCertificate = new BurpCertificate(generateX509Certificate(issuer.getPrivateKey()));
		burpCertificate.setPrivateKey(privateKey);
		burpCertificate.setPublicKey(publicKey);
		burpCertificate.setSource("Signed by " + issuer.getSubject());
		return burpCertificate;
	}

	/**
	 * Generates a new certificate and sets the fields Private/Public Key and
	 * Source of this object. The certificate is signed with the private key of
	 * "this" object.
	 *
	 * @return BurpCertificate which is self-signed.
	 * @throws CertificateEncodingException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 */
	public BurpCertificate generateSelfSignedCertificate() throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, SignatureException,
			NoSuchProviderException, InvalidKeySpecException, IOException {
		if (privateKey == null || publicKey == null) {
			generateKeyPair();
		}
		burpCertificate = new BurpCertificate(generateX509Certificate(privateKey));
		burpCertificate.setPrivateKey(privateKey);
		burpCertificate.setPublicKey(publicKey);
		burpCertificate.setSource("Self signed");
		return burpCertificate;
	}

	/**
	 * Creates a X.509v3 Certificate. The values of "this" object are used for
	 * the building process.
	 *
	 * @param privateKey
	 *            which signes the certificates
	 * @return certificate object
	 * @throws CertificateEncodingException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws IOException
	 */
	private X509Certificate generateX509Certificate(PrivateKey privateKey) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException,
			SignatureException, IOException {

		if (version != 3) {
			throw new UnsupportedOperationException("Not implemented yet.");
		}

		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				this.issuer, serial, notBefore, notAfter, subject, publicKey);

		if (hasBasicConstraints) {
			if (isCA && hasNoPathLimit) {
				builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			} else if (isCA && !hasNoPathLimit) {
				builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLimit));
			} else {
				builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			}
		}

		if (keyUsage.size() > 0) {
			int allKeyUsages = 0;
			for (int i : keyUsage) {
				allKeyUsages |= i;
			}
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(allKeyUsages));
		}

		if (extendedKeyUsage.size() > 0) {
			ASN1EncodableVector allExtendedKeyUsages = new ASN1EncodableVector();
			for (KeyPurposeId i : extendedKeyUsage) {
				allExtendedKeyUsages.add(i);
			}
			builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(allExtendedKeyUsages));
		}

		if (subjectAlternativeName.size() > 0) {
			GeneralNames generalNames = new GeneralNames(subjectAlternativeName.toArray(new GeneralName[0]));
			builder.addExtension(Extension.subjectAlternativeName, true, generalNames);
		}

		if (setSubjectKeyIdentifier) {
			JcaX509ExtensionUtils j = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.subjectKeyIdentifier, false, j.createSubjectKeyIdentifier(publicKey));
		}

		if (!subjectKeyIdentifier.isEmpty() && !setSubjectKeyIdentifier) {
			byte[] ski = CertificateHelper.hexStringToByteArray(subjectKeyIdentifier);
			builder.addExtension(Extension.subjectKeyIdentifier, true, new SubjectKeyIdentifier(ski));
		}

		if (issuerAlternativeName.size() > 0) {
			GeneralNames generalNames = new GeneralNames(issuerAlternativeName.toArray(new GeneralName[0]));
			builder.addExtension(Extension.issuerAlternativeName, true, generalNames);
		}

		if (setAuthorityKeyIdentifier && issuerCertificate != null) {
			JcaX509ExtensionUtils j = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.authorityKeyIdentifier, true, j.createAuthorityKeyIdentifier(issuerCertificate));
		}

		if (!authorityKeyIdentifier.isEmpty() && !setAuthorityKeyIdentifier) {
			byte[] aki = CertificateHelper.hexStringToByteArray(authorityKeyIdentifier);
			builder.addExtension(Extension.authorityKeyIdentifier, true, new AuthorityKeyIdentifier(aki));
		}

		for (BurpCertificateExtension e : burpCertificateExtensions) {
			ASN1OctetString oct = (ASN1OctetString) ASN1Primitive.fromByteArray(e.getExtensionValue());
			ASN1Primitive value = ASN1Primitive.fromByteArray(oct.getOctets());
			builder.addExtension(new ASN1ObjectIdentifier(e.getOid()), e.isCritical(), value);
		}

		try {
			ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(privateKey);
			return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
		} catch (OperatorCreationException e) {
			throw new SignatureException("Cannot build content signer: " + e.getMessage(), e);
		} catch (CertificateException e) {
			throw new CertificateEncodingException(e.getMessage());
		}
	}

	/**
	 * Generates a Public and Private Key with the minimum size of 512 Bytes and
	 * set the variables of this object.
	 *
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 */
	public void generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		// Minimum Key Size
		if (keySize < 512) {
			keySize = 512;
		}
		keyPairGenerator.initialize(keySize, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();
	}

	/*
	 * X.509v3 General
	 */

	public void setVersion(int version) {
		this.version = version;
	}

	public void setSerial(String serial) {
		this.serial = CertificateHelper.hexStringToBigInteger(serial);
	}

	public void setSerial(int serial) {
		this.serial = BigInteger.valueOf(serial);
	}

	public void setSerial(BigInteger serial) {
		this.serial = serial;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public void setNotBefore(String notBefore) throws ParseException {
		this.notBefore = CertificateHelper.stringToDate(notBefore);
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	public void setNotAfter(String notAfter) throws ParseException {
		this.notAfter = CertificateHelper.stringToDate(notAfter);
	}

	public void setSubject(String subject) {
		this.subject = new X500Principal(subject);
	}

	public void setSubject(X500Principal subject) {
		this.subject = subject;
	}

	public void setIssuer(String issuer) {
		this.issuer = new X500Principal(issuer);
	}

	public void setIssuer(X500Principal issuer) {
		this.issuer = issuer;
	}

	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}

	protected void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	protected void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public void setKeyPair(PublicKey publicKey, PrivateKey privateKey) {
		setPublicKey(publicKey);
		setPrivateKey(privateKey);
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		if (signatureAlgorithm.endsWith("RSA")) {
			this.signatureAlgorithm = signatureAlgorithm;
		} else {
			throw new IllegalArgumentException("Signature Algorithm not supported.");
		}
	}

	/*
	 * Extensions
	 */

	// https://github.com/bcgit/bc-java/blob/53d17ef99e30c6bd49e6eec9235e3eefca6a222d/pkix/src/test/java/org/bouncycastle/cert/test/CertTest.java#L1388

	public void addExtension(BurpCertificateExtension burpCertificateExtension) {
		burpCertificateExtensions.add(burpCertificateExtension);
	}

	public void setHasBasicConstraints(boolean hasBasicConstraints) {
		this.hasBasicConstraints = hasBasicConstraints;
	}

	public boolean hasBasicConstraints() {
		return hasBasicConstraints;
	}

	public void setIsCA(boolean isCA) {
		this.isCA = isCA;
	}

	public boolean isCa() {
		return isCA;
	}

	public void setPathLimit(int pathLimit) {
		setIsCA(true); // Implicit according to RFC 5280
		this.pathLimit = pathLimit;
	}

	public int getPathLimit() {
		return isCa() ? pathLimit : -1;
	}

	public void setHasNoPathLimit(boolean hasNoPathLimit) {
		this.hasNoPathLimit = hasNoPathLimit;
	}

	public void setKeyUsage(List<String> keyUsages) {
		this.keyUsage = new HashSet<>();
		for (String s : keyUsages) {
			addKeyUsage(s);
		}
	}

	public void addKeyUsage(String keyUsage) {
		this.keyUsage.add(ObjectIdentifier.getX509KeyUsage(keyUsage));
	}

	public void addSubjectAlternativeName(String type, String name) {
		subjectAlternativeName.add(new GeneralName(ObjectIdentifier.getX509SubjectAlternativeNames(type), name));
	}

	public void addSubjectAlternativeName(String subjectAlternativeName) {
		// Format: "name (type)"
		String type = getAlternativeType(subjectAlternativeName);
		String name = getAlternativeName(subjectAlternativeName);

		addSubjectAlternativeName(type, name);
	}

	public void addIssuerAlternativeName(String type, String name) {
		issuerAlternativeName.add(new GeneralName(ObjectIdentifier.getX509SubjectAlternativeNames(type), name));
	}

	public void addIssuerAlternativeName(String issuerAlternativeName) {
		String type = getAlternativeType(issuerAlternativeName);
		String name = getAlternativeName(issuerAlternativeName);
		addIssuerAlternativeName(type, name);
	}

	private String getAlternativeName(String alternativeString) {
		String type = "";
		// Content before braces without trailing whitespaces
		Pattern patternName = Pattern.compile("^([^(]+)[ \t]");
		Matcher matcherName = patternName.matcher(alternativeString);
		if (matcherName.find()) {
			type = matcherName.group(1);
		}
		return type;
	}

	private String getAlternativeType(String alternativeString) {
		String type = "";
		// Content between Braces; Braces are escaped using double \\
		Pattern patternType = Pattern.compile("\\(([^)]+)\\)$");
		Matcher matcherType = patternType.matcher(alternativeString);
		if (matcherType.find()) {
			type = matcherType.group(1);
		}
		return type;
	}

	public void addExtendedKeyUsage(String extendedKeyUsage) {
		this.extendedKeyUsage.add(ObjectIdentifier.getX509KeyPurposeId(extendedKeyUsage));
	}

	public void removeExtendedKeyUsage(String extendedKeyUsage) {
		this.extendedKeyUsage.remove(ObjectIdentifier.getX509KeyPurposeId(extendedKeyUsage));
	}

	public void setExtendedKeyUsage(List<String> extendedKeyUsage) {
		this.extendedKeyUsage = new HashSet<>();
		for (String s : extendedKeyUsage) {
			addExtendedKeyUsage(s);
		}
	}

	public void setSubjectKeyIdentifier(boolean setSubjectKeyIdentifier) {
		this.setSubjectKeyIdentifier = setSubjectKeyIdentifier;
	}

	public void setSubjectKeyIdentifier(String subjectKeyIdentifier) {
		this.subjectKeyIdentifier = subjectKeyIdentifier;
	}

	public void setAuthorityKeyIdentifier(boolean setAuthorityKeyIdentifier) {
		this.setAuthorityKeyIdentifier = setAuthorityKeyIdentifier;
	}

	public void setAuthorityKeyIdentifier(String authorityKeyIdentifier) {
		this.authorityKeyIdentifier = authorityKeyIdentifier;
	}

	public void setIssuserCertificate(X509Certificate issuerCertificate) {
		this.issuerCertificate = issuerCertificate;
	}

}
