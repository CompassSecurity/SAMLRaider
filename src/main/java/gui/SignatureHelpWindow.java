package gui;

import javax.swing.*;
import java.awt.*;
import java.io.Serial;

public class SignatureHelpWindow extends JFrame {

    @Serial
    private static final long serialVersionUID = 1L;


    public SignatureHelpWindow() {
        var text = """
                <h1>SAML Signature Help</h1>
                <h2>Certificate Combo Box</h2>
                Choose  a certificate of this list to sign the message or the assertion. You can manage the SAML
                Certificates in the SAML Certificates Tab.
                <h2>Resign Message / Assertion</h2>
                With the chosen certificate the message or the assertion is signed. If the message or assertion
                was signed, the signature is replaced.<br/>
                If you choose to sign the assertion, the message signature is removed, because the signature
                gets invalid.
                """;

        var textPane = new JTextPane();
        textPane.setContentType("text/html");
        textPane.setEditable(false);
        textPane.setCaret(null);
        textPane.setText(text);

        var scrollPane = new JScrollPane(textPane);

        setTitle("SAML Signature Help");
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setSize(400, 600);
        setContentPane(scrollPane);
    }

}
