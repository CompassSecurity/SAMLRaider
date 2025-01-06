package gui;

import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.Serial;

public class SamlPanelInfo extends JPanel {

	@Serial
	private static final long serialVersionUID = 1L;

	private final JLabel conditionNotBefore = new JLabel("");
	private final JLabel conditionNotAfter = new JLabel("");
	private final JLabel issuer = new JLabel("");

	private final JLabel signatureAlgorithm = new JLabel("");
	private final JLabel digestAlgorithm = new JLabel("");

	private final JLabel subject = new JLabel("");
	private final JLabel subjectConfNotBefore = new JLabel("");
	private final JLabel subjectConfNotAfter = new JLabel("");

	private final JLabel encryptedWith = new JLabel("");

	public SamlPanelInfo() {
		super();
		initialize();
	}

	private void initialize() {
		var labelConstraints = "width 150!";
		var valueConstraints = "width 200::, wrap";

		var assertionInformationPanel = new JPanel();
		assertionInformationPanel.setBorder(BorderFactory.createTitledBorder("Assertion Information"));
		assertionInformationPanel.setLayout(new MigLayout());
		assertionInformationPanel.add(new JLabel("Condition Not Before:"), labelConstraints);
		assertionInformationPanel.add(conditionNotBefore, valueConstraints);
		assertionInformationPanel.add(new JLabel("Condition Not After:"), labelConstraints);
		assertionInformationPanel.add(conditionNotAfter, valueConstraints);
		assertionInformationPanel.add(new JLabel("Issuer:"), labelConstraints);
		assertionInformationPanel.add(issuer, valueConstraints);

		var signatureInformationPanel = new JPanel();
		signatureInformationPanel.setBorder(BorderFactory.createTitledBorder("Signature Information"));
		signatureInformationPanel.setLayout(new MigLayout());
		signatureInformationPanel.add(new JLabel("Signature Algorithm:"), labelConstraints);
		signatureInformationPanel.add(signatureAlgorithm, valueConstraints);
		signatureInformationPanel.add(new JLabel("Digest Algorithm:"), labelConstraints);
		signatureInformationPanel.add(digestAlgorithm, valueConstraints);


		var subjectInformationPanel = new JPanel();
		subjectInformationPanel.setBorder(BorderFactory.createTitledBorder("Subject Information"));
		subjectInformationPanel.setLayout(new MigLayout());
		subjectInformationPanel.add(new JLabel("Subject:"), labelConstraints);
		subjectInformationPanel.add(subject, valueConstraints);
		subjectInformationPanel.add(new JLabel("Subject Conf. Not Before:"), labelConstraints);
		subjectInformationPanel.add(subjectConfNotBefore, valueConstraints);
		subjectInformationPanel.add(new JLabel("Subject Conf. Not After:"), labelConstraints);
		subjectInformationPanel.add(subjectConfNotAfter, valueConstraints);

		var encryptionInformationPanel = new JPanel();
		encryptionInformationPanel.setBorder(BorderFactory.createTitledBorder("Encryption Information"));
		encryptionInformationPanel.setLayout(new MigLayout());
		encryptionInformationPanel.add(new JLabel("Encrypted with:"), labelConstraints);
		encryptionInformationPanel.add(encryptedWith, valueConstraints);

		var informationPanelConstraints = "wrap";

		var informationPanels = new JPanel();
		informationPanels.setLayout(new MigLayout());
		informationPanels.add(assertionInformationPanel, informationPanelConstraints);
		informationPanels.add(signatureInformationPanel, informationPanelConstraints);
		informationPanels.add(subjectInformationPanel, informationPanelConstraints);
		informationPanels.add(encryptionInformationPanel, informationPanelConstraints);

		var scrollPane = new JScrollPane(informationPanels);
		scrollPane.setBorder(new EmptyBorder(0, 0, 0, 0));

		setLayout(new BorderLayout());
		add(scrollPane, BorderLayout.CENTER);
	}

	public void setIssuer(String string){
		issuer.setText(string);
	}
	
	public void setSubject(String string){
		subject.setText(string);
	}
	
	public void setConditionNotBefore(String string){
		conditionNotBefore.setText(string);
	}
	
	public void setConditionNotAfter(String string){
		conditionNotAfter.setText(string);
	}
	
	public void setSubjectConfNotBefore(String string){
		subjectConfNotBefore.setText(string);
	}

	public void setSubjectConfNotAfter(String string){
		subjectConfNotAfter.setText(string);
	}
	
	public void setSignatureAlgorithm(String string){
		signatureAlgorithm.setText(string);
	}
	
	public void setDigestAlgorithm(String string){
		digestAlgorithm.setText(string);
	}
	
	public void setEncryptionAlgorithm(String string){
		encryptedWith.setText(string);
	}

	public void clearAll(){
		setIssuer("");
		setSubject("");
		setConditionNotBefore("");
		setConditionNotAfter("");
		setSubjectConfNotBefore("");
		setSubjectConfNotAfter("");
		setSignatureAlgorithm("");
		setDigestAlgorithm("");
		setEncryptionAlgorithm("");
	}
}