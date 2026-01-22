package application;

import burp.BurpExtender;
import gui.CertificateTab;
import helpers.FileHelper;
import model.BurpCertificate;
import model.BurpCertificateBuilder;
import model.BurpCertificateExtension;
import model.BurpCertificateStore;
import model.ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class CertificateTabController implements Observable {

    private CertificateTab certificateTab;
    private Set<WeakReference<Observer>> observers;
    private BurpCertificateStore burpCertificateStore;
    private FileHelper fileHelper;

    public CertificateTabController(CertificateTab certificateTab) {
        this.certificateTab = certificateTab;
        observers = Collections.newSetFromMap(new ConcurrentHashMap<WeakReference<Observer>, Boolean>());
        burpCertificateStore = new BurpCertificateStore();
        fileHelper = new FileHelper();
        if (BurpExtender.isDebugOn) {
            importExampleCertificates();
            setCertificateTree();
        }
    }

    /*
     * Control GUI
     */

    /**
     * Update top view with all certificates.
     */
    public void setCertificateTree() {
        certificateTab.setCertificateRootNode(burpCertificateStore.getRootNode());
        notifyObservers();
    }

    /**
     * Setting the status line in GUI or print to STDOUT if no GUI and DEBUG
     * Flag is set.
     *
     * @param status message to display
     */
    private void setStatus(String status) {
        if (certificateTab != null) {
            certificateTab.setTxtStatus(status);
        } else if (BurpExtender.isDebugOn) {
            System.out.println("[Status] " + status);
        }
    }

    /**
     * Updates the bottom view with detailed certificate information
     */
    public void setCertificateDetails(BurpCertificate burpCertificate) {
        // Plugin Specific
        certificateTab.setTxtSource(burpCertificate.getSource());
        certificateTab.setChckbxPrivateKey(burpCertificate.hasPrivateKey());
        certificateTab.setSelectedBurpCertificate(burpCertificate);

        // X.509 General
        certificateTab.setTxtVersion(String.valueOf(burpCertificate.getVersionNumber()));
        certificateTab.setTxtSerialNumber(burpCertificate.getSerialNumber());
        certificateTab.setTxtSignatureAlgorithm(burpCertificate.getSignatureAlgorithm());
        certificateTab.setTxtIssuer(burpCertificate.getIssuer());
        certificateTab.setTxtNotBefore(burpCertificate.getNotBefore().toString());
        certificateTab.setTxtNotAfter(burpCertificate.getNotAfter().toString());
        certificateTab.setTxtSubject(burpCertificate.getSubject());
        certificateTab.setTxtPublicKeyAlgorithm(burpCertificate.getPublicKeyAlgorithm());

        if (burpCertificate.getPublicKeyAlgorithm().equals("RSA")) {
            certificateTab.setTxtModulus(burpCertificate.getPublicKeyModulus());
            certificateTab.setTxtExponent(burpCertificate.getPublicKeyExponent());
            certificateTab.setTxtKeySize(String.valueOf(burpCertificate.getKeySize()));
        } else {
            certificateTab.setTxtModulus("");
            certificateTab.setTxtExponent("");
            certificateTab.setTxtKeySize("");
        }
        certificateTab.setTxtSignature(burpCertificate.getSignature());

        // X.509 Extensions
        certificateTab.setIsCa(burpCertificate.isCa());
        if (burpCertificate.isCa()) {
            certificateTab.setTxtPathLimit(burpCertificate.getPathLimit());
            certificateTab.setHasNoPathLimit(burpCertificate.hasNoPathLimit());
        } else {
            certificateTab.setTxtPathLimit("");
        }

        if (burpCertificate.getKeyUsage().size() > 0) {
            certificateTab.setKeyUsage(burpCertificate.getKeyUsage());
        } else {
            certificateTab.setKeyUsage(new LinkedList<String>());
        }

        if (burpCertificate.getExtendedKeyUsage().size() > 0) {
            certificateTab.setExtendedKeyUsage(burpCertificate.getExtendedKeyUsage());
        } else {
            certificateTab.setExtendedKeyUsage(new LinkedList<String>());
        }

        if (burpCertificate.getSubjectAlternativeNames().size() > 0) {
            certificateTab.setSubjectAlternativeNames(burpCertificate.getSubjectAlternativeNames());
        } else {
            certificateTab.setSubjectAlternativeNames(new LinkedList<String>());
        }

        if (burpCertificate.getSubjectKeyIdentifier().length() > 0) {
            certificateTab.setSubjectKeyIdentifier(burpCertificate.getSubjectKeyIdentifier());
        } else {
            certificateTab.setSubjectAlternativeNames(new LinkedList<String>());
        }

        if (burpCertificate.getAuthorityKeyIdentifier().length() > 0) {
            certificateTab.setAuthorityKeyIdentifier(burpCertificate.getAuthorityKeyIdentifier());
        } else {
            certificateTab.setAuthorityKeyIdentifier("");
        }

        if (burpCertificate.getIssuerAlternativeNames().size() > 0) {
            certificateTab.setIssuerAlternativeNames(burpCertificate.getIssuerAlternativeNames());
        } else {
            certificateTab.setIssuerAlternativeNames(new LinkedList<String>());
        }

        // display only unsupported extensions which are not displayed above
        if (burpCertificate.getAllExtensions().size() > 0) {
            List<String> unsupportedExtensions = new LinkedList<>();
            for (BurpCertificateExtension extension : burpCertificate.getAllExtensions()) {
                if (!ObjectIdentifier.extensionsIsSupported(extension.getOid())) {
                    if (ObjectIdentifier.getExtension(extension.getOid()) != null) {
                        unsupportedExtensions.add(ObjectIdentifier.getExtension(extension.getOid()));
                    } else {
                        // display OID number if extension name is unknown
                        unsupportedExtensions.add(extension.getOid());
                    }
                }
            }
            certificateTab.setAllExtensions(unsupportedExtensions);
        }
    }

    /*
     * Import
     */

    /**
     * Import preloaded certificates as examples
     */
    private void importExampleCertificates() {
        if (fileHelper.startedFromJar()) {
            try {
                BurpCertificate c1 = importCertificate(fileHelper.exportRessourceFromJar("examples/certificate.pem"));
                importPrivateKeyPemFormat(c1, fileHelper.exportRessourceFromJar("examples/private_key_rsa.pem"));
                importCertificateChain(fileHelper.exportRessourceFromJar("examples/example.org_chain.pem"));
                setCertificateDetails(c1);
            } catch (IOException e) {
                setStatus("Error importing example certificates (" + e.getMessage() + ")");
            } catch (Exception e) {
                setStatus("Error (" + e.getMessage() + ")");
            }
        } else {
            BurpCertificate c1 = importCertificate("src/main/resources/examples/certificate.pem");
            importPrivateKeyPemFormat(c1, "src/main/resources/examples/private_key_rsa.pem");
            importCertificateChain("src/main/resources/examples/example.org_chain.pem");
            setCertificateDetails(c1);
        }
    }

    /**
     * Read an X.509v3 certificate from a file.
     *
     * @param filename certificate file to import
     * @return certificate
     */
    public BurpCertificate importCertificate(String filename) {
        setStatus("Importing certificate...");
        FileInputStream fis;
        try {
            fis = new FileInputStream(filename);
            byte value[] = new byte[fis.available()];
            fis.read(value);
            ByteArrayInputStream bais = new ByteArrayInputStream(value);
            fis.close();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate x509certificate = (X509Certificate) certFactory.generateCertificate(bais);
            BurpCertificate certificate = new BurpCertificate(x509certificate);
            certificate.setPublicKey(x509certificate.getPublicKey());
            certificate.setSource("Imported");
            burpCertificateStore.addCertificate(certificate);
            setCertificateTree();
            setStatus("Certificate imported.");
            setCertificateDetails(certificate);
            return certificate;
        } catch (IOException | CertificateException e) {
            setStatus("Error reading file. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setStatus("Error (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        }
        return null;
    }

    /**
     * Read an PEM encoded X.509v3 certificate
     *
     * @param inputString PEM encoded X.509 certificate
     * @return certificate
     */
    public BurpCertificate importCertificateFromString(String inputString) {
        setStatus("Importing certificate...");
        CertificateFactory certFactory;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
            var whitespaceRemoved = inputString.replaceAll("\\R", "");
            var base64Decoded = Base64.getDecoder().decode(whitespaceRemoved);
            ByteArrayInputStream bais = new ByteArrayInputStream(base64Decoded);
            X509Certificate x509certificate = (X509Certificate) certFactory.generateCertificate(bais);
            BurpCertificate certificate = new BurpCertificate(x509certificate);
            certificate.setPublicKey(x509certificate.getPublicKey());
            certificate.setSource("Imported");
            burpCertificateStore.addCertificate(certificate);
            setCertificateTree();
            setStatus("Certificate imported");
            return certificate;
        } catch (CertificateException | IllegalArgumentException e) {
            setStatus("Error reading input certificate. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setStatus("Error. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        }
        return null;
    }

    /**
     * Read and import an X.509v3 certificate chain.
     *
     * @param filename X.509v3 certificate chain (get with
     *                 <code>openssl s_client -connect example.org -showcerts</code>)
     * @return List with all certificates in chain
     */
    public List<BurpCertificate> importCertificateChain(String filename) {
        setStatus("Importing certificate chain...");
        FileInputStream fis;
        List<BurpCertificate> certificateChain = new LinkedList<>();

        try {
            fis = new FileInputStream(filename);
            byte value[] = new byte[fis.available()];
            fis.read(value);
            ByteArrayInputStream bais = new ByteArrayInputStream(value);
            fis.close();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            for (Certificate c : certFactory.generateCertificates(bais)) {
                X509Certificate x509certificate = (X509Certificate) c;
                BurpCertificate certificate = new BurpCertificate(x509certificate);
                certificate.setPublicKey(x509certificate.getPublicKey());
                certificate.setSource("Imported Chain");
                certificateChain.add(certificate);
            }

            burpCertificateStore.addCertificateChain(certificateChain);
            setCertificateTree();
            setStatus("Certificate Chain imported");
            return certificateChain;
        } catch (IOException | CertificateException e) {
            setStatus("Error reading certificate chain. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setStatus("Error (" + e.getMessage() + ")");
        }
        return null;
    }

    /**
     * Import a private key in PEM format from a file and add it to the
     * selected certificate.
     *
     * @param certificate which the private key is for.
     * @param filename    of the private key in PEM format
     */
    public void importPrivateKeyPemFormat(BurpCertificate certificate, String filename) {
        setStatus("Importing private key...");
        try (var pemParser = new PEMParser(new FileReader(filename))) {
            PrivateKeyInfo privateKeyInfo = null;
            var object = pemParser.readObject();
            if (object instanceof PEMKeyPair pemKeyPair) {
                privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
            } else if (object instanceof PrivateKeyInfo) {
                privateKeyInfo = (PrivateKeyInfo) object;
            }
            if (privateKeyInfo == null) {
                setStatus("Error importing private key.");
                return;
            }
            var converter = new JcaPEMKeyConverter();
            var privateKey = converter.getPrivateKey(privateKeyInfo);
            certificate.setPrivateKey(privateKey);
            setCertificateTree();
            setStatus("Private Key imported.");
        } catch (Exception e) {
            setStatus("Error importing private Key. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        }
    }

    /**
     * Import a private Key in PKCS8 format in DER format.
     *
     * @param certificate which the private key is for. Possible way to convert to
     *                    PKCS8:
     *                    <code>openssl pkcs8 -topk8 -inform PEM -outform DER -in privatekey.pem -out private_key_pkcs8.pem -nocrypt</code>
     * @param filename    of the PKCS8 key
     */
    public void importPrivateKeyPkcs8DerFormat(BurpCertificate certificate, String filename) {
        setStatus("Importing private key...");
        FileInputStream fis;
        File file = new File(filename);
        PrivateKey privateKey;

        try {
            fis = new FileInputStream(file);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int) file.length()];
            dis.readFully(keyBytes);
            dis.close();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
            certificate.setPrivateKey(privateKey);
            setCertificateTree();
            setStatus("Private Key imported.");
        } catch (Exception e) {
            setStatus("Error importing private Key. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        }
    }

    /*
     * Export
     */

    /**
     * Export the certificate to a file.
     *
     * @param certificate to export
     * @param filename    for the exported certificate
     */
    public void exportCertificate(BurpCertificate certificate, String filename) {
        try {
            fileHelper.exportPEMObject(certificate.getCertificate(), filename);
            setStatus("Certificate exported.");
        } catch (IOException e) {
            setStatus("Error exporting certificate (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setStatus("Error (" + e.getMessage() + ")");
        }
    }

    /**
     * Export private key in PEM format.
     *
     * @param certificate to export
     * @param filename    for the exported private key
     */
    public void exportPrivateKeyPemFormat(BurpCertificate certificate, String filename) {
        setStatus("Exporting private key...");
        try {
            fileHelper.exportPEMObject(certificate.getPrivateKey(), filename);
            setStatus("Private Key exported.");
        } catch (IOException e) {
            setStatus("Error exporting private key. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setStatus("Error (" + e.getMessage() + ")");
        }
    }

    /*
     * Clone
     */

    /**
     * Copy all X.509v3 general information and all extensions 1:1 from one
     * source certificat to one destination certificate.
     *
     * @param certificate            with the original information
     * @param burpCertificateBuilder for generating the destination certificate
     */
    private void cloneProperties(BurpCertificate certificate, BurpCertificateBuilder burpCertificateBuilder) {
        burpCertificateBuilder.setVersion(certificate.getVersionNumber());
        burpCertificateBuilder.setSerial(certificate.getSerialNumberBigInteger());
        if (certificate.getPublicKeyAlgorithm().equals("RSA")) {
            burpCertificateBuilder.setSignatureAlgorithm(certificate.getSignatureAlgorithm());
        } else {
            burpCertificateBuilder.setSignatureAlgorithm("SHA256withRSA");
        }
        burpCertificateBuilder.setIssuer(certificate.getIssuer());
        burpCertificateBuilder.setNotAfter(certificate.getNotAfter());
        burpCertificateBuilder.setNotBefore(certificate.getNotBefore());
        burpCertificateBuilder.setKeySize(certificate.getKeySize());

        for (BurpCertificateExtension extension : certificate.getAllExtensions()) {
            burpCertificateBuilder.addExtension(extension);
        }
    }

    /**
     * Clone a certificate from one source certificate. New private key material
     * is generated.
     *
     * @param certificate            to clone
     * @param burpCertificateBuilder for generating the new cloned certificate
     * @return cloned certificate
     */
    public BurpCertificate cloneCertificate(BurpCertificate certificate, BurpCertificateBuilder burpCertificateBuilder) {
        cloneProperties(certificate, burpCertificateBuilder);
        setStatus("Cloning certificate...");

        BurpCertificate burpCertificate;
        try {
            burpCertificate = burpCertificateBuilder.generateSelfSignedCertificate();
            burpCertificate.setSource("Cloned");
            burpCertificateStore.addCertificate(burpCertificate);
            setStatus("Certificate cloned.");
            setCertificateTree();
            return burpCertificate;
        } catch (IOException e) {
            setStatus("I/O error. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (CertificateEncodingException e) {
            setStatus("Problem with certificate encoding. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (InvalidKeyException e) {
            setStatus("Invalid Key.");
            BurpExtender.api.logging().logToError(e);
        } catch (NoSuchAlgorithmException e) {
            setStatus("Unsupported algorithm specified. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (SignatureException e) {
            setStatus("Error creating signature. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (InvalidKeySpecException e) {
            setStatus("Unsupported key specifications. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (NoSuchProviderException | IllegalStateException e) {
            setStatus("Error cloning certificate. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setStatus("Error (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        }
        return null;
    }

    /**
     * Clone a certificate and sign it with another private key from an issuer.
     *
     * @param certificate            to clone
     * @param burpCertificateBuilder for the cloned certificate
     * @param issuerCertificate      for signing the new certificate
     * @return cloned certificate
     */
    public BurpCertificate cloneAndSignCertificate(BurpCertificate certificate, BurpCertificateBuilder burpCertificateBuilder, BurpCertificate issuerCertificate) {
        cloneProperties(certificate, burpCertificateBuilder);

        try {
            if (!issuerCertificate.hasPrivateKey()) {
                throw new Exception("No private key found.");
            }
        } catch (Exception e) {
            setStatus("No private key found");
            BurpExtender.api.logging().logToError(e);
        }

        BurpCertificate burpCertificate;
        try {
            burpCertificate = burpCertificateBuilder.generateCertificate(issuerCertificate);
            burpCertificate.setSource("Cloned and signed by cloned " + issuerCertificate.getSubject());
            burpCertificateStore.addCertificate(burpCertificate);
            setCertificateTree();
            setStatus("Certificate cloned and signed.");
            return burpCertificate;
        } catch (CertificateEncodingException | InvalidKeyException | IllegalStateException | NoSuchAlgorithmException |
                 SignatureException | NoSuchProviderException | InvalidKeySpecException
                 | IOException e) {
            setStatus("Error cloning certificate. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setStatus("Error (" + e.getMessage() + ")");
        }
        return null;
    }

    /**
     * Clone whole certificate chain
     *
     * @param certificateChain to clone
     * @return List of cloned certificates. According to RFC 5246: Next
     * Certificate must sign previous.
     */
    public List<BurpCertificate> cloneCertificateChain(List<BurpCertificate> certificateChain) {
        List<BurpCertificate> certificates = new LinkedList<>();

        // b/c of RFC 5246 I generate them in reverse order
        Collections.reverse(certificateChain);
        BurpCertificate currentCertificate;
        BurpCertificate previousCertificate = null;
        for (BurpCertificate c : certificateChain) {
            if (previousCertificate == null) { // self-sign
                currentCertificate = cloneCertificate(c, new BurpCertificateBuilder(c.getSubject()));
            } else {
                currentCertificate = cloneAndSignCertificate(c, new BurpCertificateBuilder(c.getSubject()), previousCertificate);
            }
            // remove b/c already added in called methods above
            burpCertificateStore.removeCertificate(currentCertificate);
            certificates.add(currentCertificate);
            previousCertificate = currentCertificate;
        }
        Collections.reverse(certificates); // Restore original order
        burpCertificateStore.addCertificateChain(certificates);
        setStatus("Certificate chain cloned");
        setCertificateTree();
        return certificates;
    }

    /*
     * Create new
     */

    /**
     * Create a new X.509v3 certificate from certificate tab form. All entered
     * fields are applied and the unsupported extensions are cloned from
     * burpCertificate parameter if this option is activated.
     *
     * @param burpCertificate Unsupported extensions to clone.
     */
    public void createBurpCertificate(BurpCertificate burpCertificate) {
        setStatus("Creating certificate...");
        try {

            // X.509 General

            BurpCertificateBuilder burpCertificateBuilder = new BurpCertificateBuilder(certificateTab.getTxtSubject());
            burpCertificateBuilder.setVersion(3);
            burpCertificateBuilder.setSerial(certificateTab.getTxtSerialNumber());
            burpCertificateBuilder.setSignatureAlgorithm(certificateTab.getTxtSignatureAlgorithm());
            burpCertificateBuilder.setIssuer(certificateTab.getTxtIssuer());

            burpCertificateBuilder.setNotBefore(certificateTab.getTxtNotBefore());
            burpCertificateBuilder.setNotAfter(certificateTab.getTxtNotAfter());

            burpCertificateBuilder.setKeySize(Integer.valueOf(certificateTab.getTxtKeySize()));

            // Extensions

            if (!certificateTab.getChckbxIgnoreBasicConstraints()) {
                burpCertificateBuilder.setHasBasicConstraints(true);
                burpCertificateBuilder.setIsCA(certificateTab.isCa());
                if (certificateTab.isCa() && certificateTab.hasNoPathLimit()) {
                    burpCertificateBuilder.setHasNoPathLimit(true);
                } else if (certificateTab.isCa() && !certificateTab.hasNoPathLimit()) {
                    if (certificateTab.getTxtPathLimit() >= 0) {
                        burpCertificateBuilder.setPathLimit(certificateTab.getTxtPathLimit());
                    } else {
                        burpCertificateBuilder.setPathLimit(0);
                    }
                }
            }

            if (certificateTab.getKeyUsage().size() > 0) {
                burpCertificateBuilder.setKeyUsage(certificateTab.getKeyUsage());
            }

            if (certificateTab.getExtendedKeyUsage().size() > 0) {
                burpCertificateBuilder.setExtendedKeyUsage(certificateTab.getExtendedKeyUsage());
            }

            if (certificateTab.getSubjectAlternativeNames().size() > 0) {
                for (String s : certificateTab.getSubjectAlternativeNames()) {
                    burpCertificateBuilder.addSubjectAlternativeName(s);
                }
            }

            if (certificateTab.getIssuerAlternativeNames().size() > 0) {
                for (String s : certificateTab.getIssuerAlternativeNames()) {
                    burpCertificateBuilder.addIssuerAlternativeName(s);
                }
            }

            if (certificateTab.isAutoSubjectKeyIdentifier()) {
                burpCertificateBuilder.setSubjectKeyIdentifier(true);
            } else if (certificateTab.getSubjectKeyIdentifier().length() > 0) {
                burpCertificateBuilder.setSubjectKeyIdentifier(certificateTab.getSubjectKeyIdentifier());
            }

            if (certificateTab.isAutoAuthorityKeyIdentifier()) {
                burpCertificateBuilder.setAuthorityKeyIdentifier(true);
            } else if (certificateTab.getAuthorityKeyIdentifier().length() > 0) {
                burpCertificateBuilder.setAuthorityKeyIdentifier(certificateTab.getAuthorityKeyIdentifier());
            }

            // Unsupported Extensions - copy only unsupported ones which are not
            // implemented above
            if (certificateTab.getChckbxCopyUnsupportedExtensions()) {
                for (BurpCertificateExtension extension : burpCertificate.getAllExtensions()) {
                    if (!ObjectIdentifier.extensionsIsSupported(extension.getOid())) {
                        burpCertificateBuilder.addExtension(extension);
                    }
                }
            }

            BurpCertificate newCertificate;
            newCertificate = burpCertificateBuilder.generateSelfSignedCertificate();
            burpCertificateStore.addCertificate(newCertificate);
            setStatus("New certificate created.");
            setCertificateTree();
        } catch (CertificateEncodingException e) {
            setStatus("Problem with certificate encoding. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (InvalidKeyException e) {
            setStatus("Invalid Key. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (NoSuchAlgorithmException e) {
            setStatus("Unsupported algorithm specified. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (SignatureException e) {
            setStatus("Error creating signature. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (InvalidKeySpecException e) {
            setStatus("Unsupported key specifications. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (IOException e) {
            setStatus("I/O error (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (NoSuchProviderException | IllegalStateException e) {
            setStatus("Error creating certificate. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (ParseException e) {
            setStatus("Could not Parse Date. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (IllegalArgumentException e) {
            setStatus("Error reading input form. (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        } catch (Exception e) {
            setStatus("Error (" + e.getMessage() + ")");
            BurpExtender.api.logging().logToError(e);
        }
    }

    /*
     * Read
     */

    /**
     * Get all certificates which have a private key.
     *
     * @return List of certificates with private key.
     */
    public List<BurpCertificate> getCertificatesWithPrivateKey() {
        return burpCertificateStore.getBurpCertificatesWithPrivateKey();
    }

    /*
     * Remove
     */

    /**
     * Removes a certifiate from the certificate tree.
     *
     * @param burpCertificate to remove
     */
    public void removeBurpCertificate(BurpCertificate burpCertificate) {
        burpCertificateStore.removeCertificate(burpCertificate);
        setStatus("Certificate removed.");
        setCertificateTree();
    }

    public String getTabCaption() {
        return "SAML Raider Certificates";
    }

    public Component getUiComponent() {
        return certificateTab;
    }

    public String getSamlRequestParameterName() {
        return certificateTab.getSamlRequestParameterName();
    }

    public String getSamlResponseParameterName() {
        return certificateTab.getSamlResponseParameterName();
    }

    @Override
    public void addObserver(Observer observer) {
        this.observers.add(new WeakReference<Observer>(observer));
    }

    @Override
    public void notifyObservers() {
        for (var ref : observers) {
            var observer = ref.get();
            if (observer == null) {
                observers.remove(ref);
            } else {
                observer.update();
            }
        }
    }
}
