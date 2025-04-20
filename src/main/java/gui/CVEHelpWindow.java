package gui;

import helpers.CVE_2025_23369;
import java.awt.BorderLayout;
import java.io.Serial;
import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;

public class CVEHelpWindow extends JFrame {

    @Serial
    private static final long serialVersionUID = 1L;

    public CVEHelpWindow(String cve) {
        String description;
        if (cve.equals(CVE_2025_23369.CVE)) {
            description = """
                   <ol>
                       <li>
                           You need a SAMLResponse that is valid and accepted by the server.
                       </li>
                       <li>
                           Apply the CVE to the SAMLResponse without any prior changes. See whether the
                           SAMLResponse is still accepted. If so, this is an indicator that the server is
                           vulnerable.
                       </li>
                       <li>
                           After the CVE has been applied you can try to change one of the assertions attribute
                           to bypass authentication.
                       </li>
                   </ol>
                   """;
        } else {
            description = "no description";
        }

        var text = """
                <h1>%s</h1>
                %s
                """;

        text = text.formatted(cve, description);

        var textPane = new JTextPane();
        textPane.setContentType("text/html");
        textPane.setEditable(false);
        textPane.setCaret(null);
        textPane.setText(text);

        var scrollPane = new JScrollPane(textPane);

        setTitle(cve + " Help");
        setSize(1200, 720);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout());
        add(scrollPane, BorderLayout.CENTER);
    }
}
