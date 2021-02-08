package gui;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import java.util.List;

import javax.swing.*;

import model.BurpCertificate;
import application.SamlTabController;

public class SamlPanelAction extends JPanel {

	private static final long serialVersionUID = 1L;
	private SamlTabController controller;
	private JLabel lblMessage;
	private JComboBox<BurpCertificate> cmbboxCertificate;
	private JComboBox<String> cmbboxXSW;
	private JButton btnXSWHelp;
	private JButton btnXSWPreview;
	private JButton btnSignatureReset;
	private JButton btnXSWApply;
	private JButton btnMatchAndReplace;
	private JButton btnTestXXE;
	private JButton btnTestXSLT;
	private JButton btnRawMode;
	private JButton btnSignatureHelp;
	private JButton btnSignatureRemove;
	private JButton btnSignatureReplace;
	private JButton btnSendCertificate;
	private JButton btnSignatureAdd;
	private JTextField txtSearch;
	private JCheckBox chkRawMode;

	public SamlPanelAction() {
		initialize();
	}

	public SamlPanelAction(SamlTabController controller) {
		this.controller = controller;
		initialize();
	}

	private void initialize() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[] { 0, 0, 0};
		gridBagLayout.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		gridBagLayout.columnWeights = new double[] { 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[] { 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE };
		setLayout(gridBagLayout);


		JLabel lblSamlMsgTitle = new JLabel("SAML Message");
		GridBagConstraints gbc_lblSamlMsgTitle = new GridBagConstraints();
		gbc_lblSamlMsgTitle.insets = new Insets(10, 5, 5, 0);
		gbc_lblSamlMsgTitle.anchor = GridBagConstraints.WEST;
		gbc_lblSamlMsgTitle.gridx = 0;
		gbc_lblSamlMsgTitle.gridy = 0;
		gbc_lblSamlMsgTitle.gridwidth = 3;
		add(lblSamlMsgTitle, gbc_lblSamlMsgTitle);

		btnSignatureReset = new JButton("Reset Message");
		GridBagConstraints gbc_btnSignatureReset = new GridBagConstraints();
		gbc_btnSignatureReset.anchor = GridBagConstraints.WEST;
		gbc_btnSignatureReset.insets = new Insets(5, 5, 0, 0);
		gbc_btnSignatureReset.gridx = 1;
		gbc_btnSignatureReset.gridy = 1;
		add(btnSignatureReset, gbc_btnSignatureReset);
		btnSignatureReset.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.resetMessage();
			}
		});

		chkRawMode = new JCheckBox("Raw Mode (don't parse XML before sending)");
		GridBagConstraints gbc_chkRawMode = new GridBagConstraints();
		gbc_chkRawMode.anchor = GridBagConstraints.WEST;
		gbc_chkRawMode.insets = new Insets(5, 5, 0, 0);
		gbc_chkRawMode.gridx = 2;
		gbc_chkRawMode.gridy = 1;
		gbc_chkRawMode.gridwidth = 2;
		add(chkRawMode, gbc_chkRawMode);
		chkRawMode.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.setRawMode(chkRawMode.isSelected());
			}
		});

		JLabel lblXSWTitle = new JLabel("XSW Attacks");
		GridBagConstraints gbc_lblXSWTitle = new GridBagConstraints();
		gbc_lblXSWTitle.insets = new Insets(10, 5, 5, 0);
		gbc_lblXSWTitle.anchor = GridBagConstraints.WEST;
		gbc_lblXSWTitle.gridx = 0;
		gbc_lblXSWTitle.gridy = 3;
		gbc_lblXSWTitle.gridwidth = 3;
		add(lblXSWTitle, gbc_lblXSWTitle);

		btnXSWHelp = new JButton("?");
		GridBagConstraints gbc_btnXSWHelp = new GridBagConstraints();
		gbc_btnXSWHelp.insets = new Insets(5, 5, 0, 0);
		gbc_btnXSWHelp.gridx = 0;
		gbc_btnXSWHelp.gridy = 4;
		btnXSWHelp.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.showXSWHelp();
			}
		});
		add(btnXSWHelp, gbc_btnXSWHelp);

		cmbboxXSW = new JComboBox<String>();
		GridBagConstraints gbc_cmbboxXSW = new GridBagConstraints();
		gbc_cmbboxXSW.insets = new Insets(5, 5, 0, 0);
		gbc_cmbboxXSW.anchor = GridBagConstraints.WEST;
		gbc_cmbboxXSW.gridx = 1;
		gbc_cmbboxXSW.gridy = 4;
		gbc_cmbboxXSW.gridwidth = 3;
		add(cmbboxXSW, gbc_cmbboxXSW);

		btnXSWPreview = new JButton("Preview in Browser...");
		GridBagConstraints gbc_btnXSWPreview = new GridBagConstraints();
		gbc_btnXSWPreview.anchor = GridBagConstraints.WEST;
		gbc_btnXSWPreview.insets = new Insets(5, 5, 0, 0);
		gbc_btnXSWPreview.gridx = 1;
		gbc_btnXSWPreview.gridy = 5;
		btnXSWPreview.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.showXSWPreview();
			}
		});
		add(btnXSWPreview, gbc_btnXSWPreview);

		btnXSWApply = new JButton("Apply XSW");
		GridBagConstraints gbc_btnXSWApply = new GridBagConstraints();
		gbc_btnXSWApply.insets = new Insets(5, 5, 0, 0);
		gbc_btnXSWApply.anchor = GridBagConstraints.WEST;
		gbc_btnXSWApply.gridx = 3;
		gbc_btnXSWApply.gridy = 5;
		btnXSWApply.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.applyXSW();				
			}
		});
		add(btnXSWApply, gbc_btnXSWApply);
		
		btnMatchAndReplace = new JButton("Match and Replace");
		GridBagConstraints gbc_btnMatchAndReplace = new GridBagConstraints();
		gbc_btnMatchAndReplace.insets = new Insets(5, 5, 0, 0);
		gbc_btnMatchAndReplace.anchor = GridBagConstraints.WEST;
		gbc_btnMatchAndReplace.gridx = 2;
		gbc_btnMatchAndReplace.gridy = 5;
		btnMatchAndReplace.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				showMatchAndReplaceDialog();
			}
		});
		add(btnMatchAndReplace, gbc_btnMatchAndReplace);

		JLabel lblXmlAttacksTitle = new JLabel("XML Attacks");
		GridBagConstraints gbc_lblXmlAttacksTitle = new GridBagConstraints();
		gbc_lblXmlAttacksTitle.anchor = GridBagConstraints.WEST;
		gbc_lblXmlAttacksTitle.insets = new Insets(10, 5, 5, 0);
		gbc_lblXmlAttacksTitle.gridx = 0;
		gbc_lblXmlAttacksTitle.gridy = 7;
		gbc_lblXmlAttacksTitle.gridwidth = 3;
		add(lblXmlAttacksTitle, gbc_lblXmlAttacksTitle);

		btnTestXXE = new JButton("Test XXE");
		GridBagConstraints gbc_btnTestXXE = new GridBagConstraints();
		gbc_btnTestXXE.insets = new Insets(5, 5, 0, 0);
		gbc_btnTestXXE.anchor = GridBagConstraints.WEST;
		gbc_btnTestXXE.gridx = 1;
		gbc_btnTestXXE.gridy = 8;
		btnTestXXE.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String collabUrl = JOptionPane.showInputDialog(btnXSWApply, 
				        "Enter Burp Collaborator URL (e.g. https://xyz.burpcollaborator.net)");
				if(collabUrl != null) {
					controller.applyXXE(collabUrl);
				}
			}
		});
		add(btnTestXXE, gbc_btnTestXXE);
		
		btnTestXSLT = new JButton("Test XSLT");
		GridBagConstraints gbc_btnTestXSLT = new GridBagConstraints();
		gbc_btnTestXSLT.insets =new Insets(5, 5, 0, 0);
		gbc_btnTestXSLT.anchor = GridBagConstraints.WEST;
		gbc_btnTestXSLT.gridx = 2;
		gbc_btnTestXSLT.gridy = 8;
		btnTestXSLT.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String collabUrl = JOptionPane.showInputDialog(btnXSWApply, 
				        "Enter Burp Collaborator URL (e.g. https://xyz.burpcollaborator.net)");
				if(collabUrl != null) {
					controller.applyXSLT(collabUrl);
				}
			}
		});
		add(btnTestXSLT, gbc_btnTestXSLT);

		JLabel lblSignatureTitle = new JLabel("XML Signature Attacks");
		GridBagConstraints gbc_lblSignatureTitle = new GridBagConstraints();
		gbc_lblSignatureTitle.anchor = GridBagConstraints.WEST;
		gbc_lblSignatureTitle.insets = new Insets(10, 5, 5, 0);
		gbc_lblSignatureTitle.gridx = 0;
		gbc_lblSignatureTitle.gridy = 10;
		gbc_lblSignatureTitle.gridwidth = 3;
		add(lblSignatureTitle, gbc_lblSignatureTitle);

		btnSignatureHelp = new JButton("?");
		GridBagConstraints gbc_btnSignatureHelp = new GridBagConstraints();
		gbc_btnSignatureHelp.insets = new Insets(5, 5, 0, 0);
		gbc_btnSignatureHelp.gridx = 0;
		gbc_btnSignatureHelp.gridy = 11;
		btnSignatureHelp.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.showSignatureHelp();
			}
		});
		add(btnSignatureHelp, gbc_btnSignatureHelp);

		cmbboxCertificate = new JComboBox<BurpCertificate>();
		GridBagConstraints gbc_cmbboxCertificate = new GridBagConstraints();
		gbc_cmbboxCertificate.insets = new Insets(5, 5, 0, 0);
		gbc_cmbboxCertificate.anchor = GridBagConstraints.WEST;
		gbc_cmbboxCertificate.gridx = 1;
		gbc_cmbboxCertificate.gridy = 12;
		gbc_cmbboxCertificate.gridwidth = 3;
		add(cmbboxCertificate, gbc_cmbboxCertificate);

		btnSignatureRemove = new JButton("Remove Signatures");
		btnSignatureRemove.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.removeSignature();
			}
		});
		GridBagConstraints gbc_btnSignatureRemove = new GridBagConstraints();
		gbc_btnSignatureRemove.anchor = GridBagConstraints.WEST;
		gbc_btnSignatureRemove.insets = new Insets(5, 5, 0, 0);
		gbc_btnSignatureRemove.gridx = 1;
		gbc_btnSignatureRemove.gridy = 11;
		add(btnSignatureRemove, gbc_btnSignatureRemove);

		btnSignatureReplace = new JButton("(Re-)Sign Assertion");
		btnSignatureReplace.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.resignAssertion();
			}
		});
		GridBagConstraints gbc_btnSignatureReplace = new GridBagConstraints();
		gbc_btnSignatureReplace.anchor = GridBagConstraints.WEST;
		gbc_btnSignatureReplace.insets = new Insets(5, 5, 0, 0);
		gbc_btnSignatureReplace.gridx = 1;
		gbc_btnSignatureReplace.gridy = 13;
		add(btnSignatureReplace, gbc_btnSignatureReplace);


		btnSendCertificate = new JButton("Send Certificate to SAML Raider Certificates");
		GridBagConstraints gbc_btnSendCertificate = new GridBagConstraints();
		gbc_btnSendCertificate.anchor = GridBagConstraints.WEST;
		gbc_btnSendCertificate.insets = new Insets(5, 5, 0, 0);
		gbc_btnSendCertificate.gridx = 2;
		gbc_btnSendCertificate.gridy = 11;
		gbc_btnSendCertificate.gridwidth = 2;
		btnSendCertificate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.sendToCertificatesTab();
			}
		});
		add(btnSendCertificate, gbc_btnSendCertificate);

		btnSignatureAdd = new JButton("(Re-)Sign Message");
		GridBagConstraints gbc_btnSignatureAdd = new GridBagConstraints();
		gbc_btnSignatureAdd.anchor = GridBagConstraints.WEST;
		btnSignatureAdd.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				controller.resignMessage();
			}
		});
		gbc_btnSignatureAdd.insets = new Insets(5, 5, 0, 0);
		gbc_btnSignatureAdd.gridx = 2;
		gbc_btnSignatureAdd.gridy = 13;
		add(btnSignatureAdd, gbc_btnSignatureAdd);

		
		lblMessage = new JLabel("");
		lblMessage.setBackground(new Color(255, 250, 205));
		lblMessage.setForeground(new Color(255, 140, 0));
		GridBagConstraints gbc_lblMessage = new GridBagConstraints();
		gbc_lblMessage.anchor = GridBagConstraints.WEST;
		gbc_lblMessage.gridwidth = 3;
		gbc_lblMessage.insets = new Insets(20, 5, 10, 0);
		gbc_lblMessage.gridx = 0;
		gbc_lblMessage.gridy = 14;
		add(lblMessage, gbc_lblMessage);
	}

	public JLabel getInfoMessageLabel() {
		return lblMessage;
	}

	public void setCertificateList(List<BurpCertificate> list) {
		DefaultComboBoxModel<BurpCertificate> model = new DefaultComboBoxModel<BurpCertificate>();

		for (BurpCertificate cert : list) {
			model.addElement(cert);
		}
		cmbboxCertificate.setModel(model);
	}

	public BurpCertificate getSelectedCertificate() {
		return (BurpCertificate) cmbboxCertificate.getSelectedItem();
	}

	public void setXSWList(String[] xswTypes) {
		DefaultComboBoxModel<String> model = new DefaultComboBoxModel<String>(xswTypes);
		cmbboxXSW.setModel(model);
	}

	public String getSelectedXSW() {
		return (String) cmbboxXSW.getSelectedItem();
	}
	
	public String getSearchText(){
		return txtSearch.getText();
	}

	public boolean isRawModeEnabled(){ return chkRawMode.isSelected(); }

	public void setRawModeEnabled(boolean rawModeEnabled) {
		chkRawMode.setSelected(rawModeEnabled);
	}

	public void disableControls() {
		cmbboxCertificate.setEnabled(false);
		cmbboxXSW.setEnabled(false);
		btnXSWHelp.setEnabled(false);
		btnXSWPreview.setEnabled(false);
		btnSignatureReset.setEnabled(false);
		btnXSWApply.setEnabled(false);
		btnSignatureHelp.setEnabled(false);
		btnSignatureRemove.setEnabled(false);
		btnSignatureReplace.setEnabled(false);
		btnSendCertificate.setEnabled(false);
		btnSignatureAdd.setEnabled(false);
		btnMatchAndReplace.setEnabled(false);
		btnTestXXE.setEnabled(false);
		btnTestXSLT.setEnabled(false);
		chkRawMode.setEnabled(false);
		this.revalidate();
	}

	public void enableControls() {
		cmbboxCertificate.setEnabled(true);
		cmbboxXSW.setEnabled(true);
		btnXSWHelp.setEnabled(true);
		btnXSWPreview.setEnabled(true);
		btnSignatureReset.setEnabled(true);
		btnXSWApply.setEnabled(true);
		btnSignatureHelp.setEnabled(true);
		btnSignatureRemove.setEnabled(true);
		btnSignatureReplace.setEnabled(true);
		btnSendCertificate.setEnabled(true);
		btnSignatureAdd.setEnabled(true);
		btnMatchAndReplace.setEnabled(true);
		btnTestXXE.setEnabled(true);
		btnTestXSLT.setEnabled(true);
		chkRawMode.setEnabled(true);
		this.revalidate();
	}

	private void showMatchAndReplaceDialog() {
		HashMap<String, String> matchAndReplaceMap = controller.getMatchAndReplaceMap();
		
	    JPanel dialogPanel = new JPanel();
	    dialogPanel.setLayout(new BorderLayout());
	    dialogPanel.add(new JLabel("Match and replace rules takes effect after apply XSW"), BorderLayout.NORTH);
	    
	    JPanel listPanel = new JPanel();
	    JTextField matchInputText = new JTextField();
	    JTextField replaceInputText = new JTextField();
	    
	    JButton addEntryButton = new JButton("\u2795");
	    addEntryButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				if(matchInputText.getText() != "" && replaceInputText.getText() != "") {
					matchAndReplaceMap.put(matchInputText.getText(), replaceInputText.getText());
					updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
					SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
				}
			}
		});
	    	    
	    updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
	    JOptionPane.showMessageDialog(this, listPanel, "Apply XSW - Match and Replace", JOptionPane.PLAIN_MESSAGE);
	}
	
	private void updateMatchAndReplaceList(JPanel listPanel, JTextField matchInputText, JTextField replaceInputText, JButton addEntryButton) {
		HashMap<String, String> matchAndReplaceMap = controller.getMatchAndReplaceMap();
		listPanel.setLayout(new GridBagLayout());
		listPanel.removeAll();
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridx = 0;
		c.gridy = 0;
		listPanel.add(new JLabel("Match:                                          "),c);
		c.gridx = 1;
	    listPanel.add(new JLabel("Replace:                                        "),c);
	    c.gridx = 0;
		c.gridy = 1;
	    listPanel.add(matchInputText,c);
	    c.gridx = 1;
	    listPanel.add(replaceInputText,c);
	    c.gridx = 2;
	    listPanel.add(addEntryButton,c);
	    
	    c.gridy = 2;
		for(String matchRule : matchAndReplaceMap.keySet()) {
			c.gridx = 0;
			listPanel.add(new JLabel(matchRule),c);
			
			c.gridx = 1;
			listPanel.add(new JLabel(matchAndReplaceMap.get(matchRule)),c);
			JButton deleteEntryBtn = new JButton("\u2796");
			deleteEntryBtn.addActionListener(new ActionListener() {
				
				@Override
				public void actionPerformed(ActionEvent e) {
					matchAndReplaceMap.remove(matchRule);
					updateMatchAndReplaceList(listPanel, matchInputText, replaceInputText, addEntryButton);
					SwingUtilities.getWindowAncestor((Component) e.getSource()).pack();
				}
			});
			c.gridx = 2;
			listPanel.add(deleteEntryBtn,c);
			c.gridy++;
		}
		listPanel.revalidate();
	}
}
