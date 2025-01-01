package gui;

import javax.swing.*;
import java.awt.*;
import java.io.Serial;

public class XSWHelpWindow extends JFrame {

    @Serial
    private static final long serialVersionUID = 1L;

    public XSWHelpWindow() {

        var imageURL = this.getClass().getClassLoader().getResource("xswlist.png");

        var text = """
                <p>With xml wrapping attacks you try to trick the xml signature validator into validating an signature
                of an element while evaluating an other element. The XSWs in the image are supported.
                The blue element represents the signature. The green one represents the original element, which is
                correctly signed. The red one represents the falsly evaluated element, if the validating is not
                correctly implemented. Mind that the first two XSWs can be used for signed responses only whereas
                the other ones can be used for signed assertions only. These XSW are taken from this paper:
                Somorovsky, Juraj, et al. "On Breaking SAML: Be Whoever You Want to Be." USENIX Security Symposium.
                2012. Please check out this paper for further information.</p>
                <p><img src="%s" alt="xswlist.png" width="1160"/></p>
                """;

        text = text.formatted(imageURL);

        var textPane = new JTextPane();
        textPane.setContentType("text/html");
        textPane.setEditable(false);
        textPane.setCaret(null);
        textPane.setText(text);

        var scrollPane = new JScrollPane(textPane);

        setTitle("XML Signature Wrapping Help");
        setSize(1200, 720);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());
        add(scrollPane, BorderLayout.CENTER);
    }
}
