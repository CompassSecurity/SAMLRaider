package gui;

import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;

/// Modal dialog for the Build+Encrypt Assertion flow.
/// Pre-filled with values extracted from the current SAML response; user only
/// needs to supply the target NameID.
public class EncryptAssertionDialog extends JDialog {

    private final JTextField txtIssuer;
    private final JTextField txtNameIdFormat;
    private final JTextField txtNameId;
    private final JTextField txtRecipient;
    private final JTextField txtAudience;
    private boolean confirmed = false;

    public EncryptAssertionDialog(Window parent,
                                  String issuer,
                                  String nameIdFormat,
                                  String recipient,
                                  String audience) {
        super(parent, "Build & Encrypt Assertion", ModalityType.APPLICATION_MODAL);

        txtIssuer       = new JTextField(issuer, 54);
        txtNameIdFormat = new JTextField(nameIdFormat, 54);
        txtNameId       = new JTextField(54);
        txtRecipient    = new JTextField(recipient, 54);
        txtAudience     = new JTextField(audience, 54);

        JLabel nameIdLabel = new JLabel("NameID (target user):");
        nameIdLabel.setFont(nameIdLabel.getFont().deriveFont(Font.BOLD));

        JPanel form = new JPanel(new MigLayout("insets 14, gap 6 8", "[][grow,fill]"));
        form.add(new JLabel("Issuer:"));
        form.add(txtIssuer, "wrap");
        form.add(new JLabel("NameID Format:"));
        form.add(txtNameIdFormat, "wrap");
        form.add(nameIdLabel);
        form.add(txtNameId, "wrap");
        form.add(new JLabel("Recipient (ACS URL):"));
        form.add(txtRecipient, "wrap");
        form.add(new JLabel("Audience:"));
        form.add(txtAudience, "wrap");

        JButton btnOk     = new JButton("Build & Encrypt");
        JButton btnCancel = new JButton("Cancel");
        btnOk.addActionListener(e -> { confirmed = true; dispose(); });
        btnCancel.addActionListener(e -> dispose());

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 6));
        btns.add(btnCancel);
        btns.add(btnOk);

        JPanel root = new JPanel(new BorderLayout());
        root.add(form, BorderLayout.CENTER);
        root.add(btns, BorderLayout.SOUTH);

        setContentPane(root);
        getRootPane().setDefaultButton(btnOk);
        pack();
        setResizable(false);
        setLocationRelativeTo(parent);
    }

    public boolean isConfirmed()    { return confirmed; }
    public String getIssuer()       { return txtIssuer.getText().trim(); }
    public String getNameIdFormat() { return txtNameIdFormat.getText().trim(); }
    public String getNameId()       { return txtNameId.getText().trim(); }
    public String getRecipient()    { return txtRecipient.getText().trim(); }
    public String getAudience()     { return txtAudience.getText().trim(); }
}
