package application;

import gui.CertificateTab;
import java.security.Security;
import java.util.List;
import model.BurpCertificate;
import model.BurpCertificateStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class CertificateStoreTest {

    BurpCertificateStore burpCertificateStore;

    @BeforeEach
    public void setup() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        burpCertificateStore = new BurpCertificateStore();

        // Single Certificate
        BurpCertificateBuilder b1 = new BurpCertificateBuilder("CN=example.net");
        BurpCertificate c1 = b1.generateSelfSignedCertificate();
        burpCertificateStore.addCertificate(c1);

        // Single Certificate
        BurpCertificateBuilder b2 = new BurpCertificateBuilder("CN=foobar.net");
        BurpCertificate c2 = b2.generateSelfSignedCertificate();
        burpCertificateStore.addCertificate(c2);

        // Single Certificate
        BurpCertificateBuilder b3 = new BurpCertificateBuilder("CN=gugus.lan");
        BurpCertificate c3 = b3.generateSelfSignedCertificate();
        burpCertificateStore.addCertificate(c3);

        // Certificate Chain
        CertificateTabController certificateTabController = new CertificateTabController(new CertificateTab());
        List<BurpCertificate> certificateChain = certificateTabController.importCertificateChain("src/test/resources/hsr_chain.pem");
        burpCertificateStore.addCertificateChain(certificateChain);

        certificateTabController.cloneCertificateChain(certificateChain);
    }

    @Test
    public void certsWithPrivateKeyCountIsCorrect() {
        assertEquals(3, burpCertificateStore.getBurpCertificatesWithPrivateKey().size());
    }
}
