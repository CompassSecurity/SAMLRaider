package gui;

import application.CertificateTabController;
import com.formdev.flatlaf.ui.FlatTreeUI;
import model.BurpCertificate;
import model.BurpCertificateBuilder;
import model.ObjectIdentifier;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeSelectionModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class CertificateTab extends JPanel {

    private CertificateTabController certificateTabController;

    private JTree certificateTree;
    private DefaultTreeModel certificateTreeModel;
    private JFileChooser fc = new JFileChooser();
    private BurpCertificate selectedBurpCertificate;
    private JTextField txtSource;
    private JCheckBox chckbxPrivateKey;
    private JButton btnExportPrivateKeyRSA;
    private JTextField txtSerialNumber;
    private JTextField txtIssuer;
    private JTextField txtSubject;
    private JTextArea txtModulus;
    private JTextField txtExponent;
    private JTextField txtVersion;
    private JComboBox<String> txtSignatureAlgorithm;
    private JTextField txtNotBefore;
    private JTextField txtNotAfter;
    private JComboBox<String> txtPublicKeyAlgorithm;
    private JTextField txtKeySize;
    private JTextPane txtStatus;
    private JTextArea txtSignature;
    private JTextField txtSamlRequestParamName;
    private JTextField txtSamlResponseParamName;
    private JCheckBox chckbxIgnoreBasicConstraints;
    private JCheckBox chckbxCa;
    private JCheckBox chckbxNoPathLimit;
    private JTextField txtPathLimit;
    private List<JCheckBox> jbxKeyUsages;
    private List<JCheckBox> jbxExtendedKeyUsages;
    private JList<String> lstSubjectAlternativeNames;
    private DefaultListModel<String> lstSubjectAlternativeNamesModel;
    private JList<String> lstIssuerAlternativeNames;
    private DefaultListModel<String> lstIssuerAlternativeNamesModel;
    private JTextField txtSubjectAlternativeNameName;
    private JTextField txtIssuerAlternativeNameName;
    private JTextField txtSubjectkeyidentifier;
    private JCheckBox chckbxAutosubjectkeyidentifier;
    private JTextField txtAuthoritykeyidentifier;
    private JCheckBox chckbxAutoauthoritykeyidetifier;
    private JCheckBox chckbxCopyUnsupportedExtensions;
    private JList<String> lstUnsupportedExtensions;
    private DefaultListModel<String> lstAllExtensionsModel;
    private JComboBox<String> cbbSubjectAlternativeNameType;
    private JComboBox<String> cbbIssuerAlternativeNameType;

    public CertificateTab() {
        super();
        setPreferredSize(new Dimension(1024, 786));
        initializeGui();
    }

    private void initializeGui() {
        JButton btnImport = new JButton("Import");
        btnImport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int returnVal = fc.showOpenDialog(CertificateTab.this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    certificateTabController.importCertificate(file.getAbsolutePath());
                } else {
                    System.out.println("Cancelled by user");
                }
            }
        });

        JButton btnImportCertificateChain = new JButton("Import Chain");
        btnImportCertificateChain.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int returnVal = fc.showOpenDialog(CertificateTab.this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    certificateTabController.importCertificateChain(file.getAbsolutePath());
                } else {
                    System.out.println("Cancelled by user");
                }
            }
        });

        JButton btnExport = new JButton("Export");
        btnExport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int returnVal = fc.showOpenDialog(CertificateTab.this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    certificateTabController.exportCertificate(selectedBurpCertificate, file.getAbsolutePath());
                } else {
                    System.out.println("Cancelled by user");
                }
            }
        });

        JButton btnDelete = new JButton("Delete");
        btnDelete.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                certificateTabController.removeBurpCertificate(selectedBurpCertificate);
            }
        });

        JButton btnClone = new JButton("Clone");
        btnClone.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                certificateTabController.cloneCertificate(selectedBurpCertificate, new BurpCertificateBuilder(selectedBurpCertificate.getSubject()));
            }
        });


        JButton btnCloneChain = new JButton("Clone Chain");
        btnCloneChain.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                List<BurpCertificate> toClone = new LinkedList<>();
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) certificateTree.getLastSelectedPathComponent();
                certificateTreeModel.getPathToRoot(node);

                for (Object n : node.getUserObjectPath()) {
                    if (n instanceof BurpCertificate) {
                        toClone.add((BurpCertificate) n);
                    }
                }
                Collections.reverse(toClone);
                certificateTabController.cloneCertificateChain(toClone);
            }
        });

        certificateTreeModel = new DefaultTreeModel(new DefaultMutableTreeNode("root"));
        certificateTree = new JTree(certificateTreeModel);
        certificateTree.setUI(new FlatTreeUI());
        certificateTree.setRootVisible(false);
        certificateTree.setShowsRootHandles(true);
        certificateTree.setCellRenderer((tree, value, selected, expanded, leaf, row, hasFocus) -> {
            var label = new JLabel();
            label.setText(value.toString());
            if (leaf) {
                label.setIcon(UIManager.getIcon("Tree.leafIcon"));
            } else if (expanded) {
                label.setIcon(UIManager.getIcon("Tree.openIcon"));
            } else {
                label.setIcon(UIManager.getIcon("Tree.closedIcon"));
            }
            if (selected) {
                label.setForeground(UIManager.getColor("Tree.selectionForeground"));
                label.setBackground(UIManager.getColor("Tree.selectionBackground"));
            } else {
                label.setForeground(UIManager.getColor("Tree.textForeground"));
                label.setBackground(UIManager.getColor("Tree.textBackground"));
            }
            return label;
        });
        certificateTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        certificateTree.addTreeSelectionListener(event -> {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) certificateTree.getLastSelectedPathComponent();
            if (node == null || node.getUserObject() instanceof String) {
                return;
            }
            BurpCertificate burpCertificate = (BurpCertificate) node.getUserObject();
            certificateTabController.setCertificateDetails(burpCertificate);
        });

        txtStatus = new JTextPane();
        txtStatus.setEditable(false);

        var samlRequestParamNameLabel = new JLabel("SAML Request Param Name");
        txtSamlRequestParamName = new JTextField("SAMLRequest");

        var samlResponseParamNameLabel = new JLabel("SAML Response Param Name");
        txtSamlResponseParamName = new JTextField("SAMLResponse");

        txtSource = new JTextField();
        txtSource.setEditable(false);

        chckbxPrivateKey = new JCheckBox("Private Key");
        chckbxPrivateKey.setEnabled(false);

        JButton btnImportPrivateKeyPKCS8 = new JButton("Import PKCS#8 DER");
        btnImportPrivateKeyPKCS8.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int returnVal = fc.showOpenDialog(CertificateTab.this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    certificateTabController.importPKCS8(selectedBurpCertificate, file.getAbsolutePath());
                } else {
                    System.out.println("Cancelled by user");
                }
            }
        });

        JButton btnImportPrivateKeyRSA = new JButton("Import RSA PEM");
        btnImportPrivateKeyRSA.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int returnVal = fc.showOpenDialog(CertificateTab.this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    certificateTabController.importPrivateKey(selectedBurpCertificate, file.getAbsolutePath());
                } else {
                    System.out.println("Cancelled by user");
                }
            }
        });

        btnExportPrivateKeyRSA = new JButton("Export RSA PEM");
        btnExportPrivateKeyRSA.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int returnVal = fc.showOpenDialog(CertificateTab.this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = fc.getSelectedFile();
                    certificateTabController.exportPrivateKey(selectedBurpCertificate, file.getAbsolutePath());
                } else {
                    System.out.println("Cancelled by user");
                }
            }
        });

        JButton btnSaveAndSelfsign = new JButton("Save and Self-Sign");
        btnSaveAndSelfsign.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                certificateTabController.createBurpCertificate(selectedBurpCertificate);
            }
        });

        txtVersion = new JTextField();
        txtVersion.setEditable(false);

        txtSerialNumber = new JTextField();
        txtSerialNumber.setToolTipText("Serial Number in Hex");

        txtSignatureAlgorithm = new JComboBox<String>((String[]) ObjectIdentifier.getAllSignatureAlgorithms().toArray(new String[0]));
        txtSignatureAlgorithm.setSelectedIndex(-1);
        txtSignatureAlgorithm.setEditable(true);

        txtIssuer = new JTextField();

        txtNotBefore = new JTextField();
        txtNotBefore.setToolTipText("Format: \"May 23 23:05:42 2005 GMT\" or \"Mon May 23 23:05:42 CET 2005\"");

        txtNotAfter = new JTextField();

        txtSubject = new JTextField();

        txtPublicKeyAlgorithm = new JComboBox<>(ObjectIdentifier.getAllPublicKeyAlgorithms().toArray(new String[0]));
        txtPublicKeyAlgorithm.setSelectedIndex(-1);
        txtPublicKeyAlgorithm.setEditable(true);

        txtKeySize = new JTextField();

        txtModulus = new JTextArea();
        txtModulus.setEditable(false);
        txtModulus.setLineWrap(true);

        txtExponent = new JTextField();
        txtExponent.setEditable(false);

        txtSignature = new JTextArea();
        txtSignature.setEditable(false);
        txtSignature.setLineWrap(true);

        chckbxCa = new JCheckBox("CA");
        chckbxCa.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                txtPathLimit.setEnabled(chckbxCa.isSelected() && !chckbxNoPathLimit.isSelected());
                chckbxNoPathLimit.setEnabled(chckbxCa.isSelected());
            }
        });

        txtPathLimit = new JTextField();

        chckbxNoPathLimit = new JCheckBox("No Path Limit");
        chckbxNoPathLimit.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                txtPathLimit.setEnabled(!chckbxNoPathLimit.isSelected());
                txtPathLimit.setText("");
            }
        });

        chckbxIgnoreBasicConstraints = new JCheckBox("Don't copy.");
        chckbxIgnoreBasicConstraints.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                boolean isSelected = chckbxIgnoreBasicConstraints.isSelected();
                chckbxCa.setEnabled(!isSelected);
                chckbxNoPathLimit.setEnabled(!isSelected);
                if (isSelected) {
                    txtPathLimit.setEnabled(false);
                } else {
                    txtPathLimit.setEnabled(!chckbxNoPathLimit.isSelected());
                }
            }
        });

        jbxKeyUsages = new LinkedList<>();
        for (String s : ObjectIdentifier.getAllKeyUsages()) {
            jbxKeyUsages.add(new JCheckBox(s));
        }

        jbxExtendedKeyUsages = new LinkedList<>();
        for (String s : ObjectIdentifier.getAllExtendedKeyUsages()) {
            jbxExtendedKeyUsages.add(new JCheckBox(s));
        }

        lstSubjectAlternativeNamesModel = new DefaultListModel<>();
        lstSubjectAlternativeNames = new JList<String>(lstSubjectAlternativeNamesModel);

        JButton btnDeletesubjectalternativename = new JButton("Delete");
        btnDeletesubjectalternativename.setAlignmentY(Component.TOP_ALIGNMENT);
        btnDeletesubjectalternativename.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int selectedIndex = lstSubjectAlternativeNames.getSelectedIndex();
                if (selectedIndex != -1) {
                    lstSubjectAlternativeNamesModel.remove(selectedIndex);
                }
            }
        });

        cbbSubjectAlternativeNameType = new JComboBox<>(ObjectIdentifier.getAllSubjectAlternativeNames().toArray(new String[0]));

        txtSubjectAlternativeNameName = new JTextField();

        JButton tbnAddSubjectAlternativeName = new JButton("Add");
        tbnAddSubjectAlternativeName.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                System.out.println(txtSubjectAlternativeNameName.getText());
                addSubjectAlternativeNames(txtSubjectAlternativeNameName.getText() + " (" + cbbSubjectAlternativeNameType.getSelectedItem() + ")");
            }
        });


        lstIssuerAlternativeNamesModel = new DefaultListModel<>();
        lstIssuerAlternativeNames = new JList<String>();
        lstIssuerAlternativeNames.setModel(lstIssuerAlternativeNamesModel);

        JButton btnBtndeleteissueralternativename = new JButton("Delete");
        btnBtndeleteissueralternativename.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                int selectedIndex = lstIssuerAlternativeNames.getSelectedIndex();
                if (selectedIndex != -1) {
                    lstIssuerAlternativeNamesModel.remove(selectedIndex);
                }
            }
        });

        cbbIssuerAlternativeNameType = new JComboBox<>(ObjectIdentifier.getAllSubjectAlternativeNames().toArray(new String[0]));

        txtIssuerAlternativeNameName = new JTextField();

        JButton btnAddissueralternativename = new JButton("Add");
        btnAddissueralternativename.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                addIssuerAlternativeNames(txtIssuerAlternativeNameName.getText() + " (" + cbbIssuerAlternativeNameType.getSelectedItem() + ")");
            }
        });

        txtSubjectkeyidentifier = new JTextField();

        chckbxAutosubjectkeyidentifier = new JCheckBox("Auto generate from Public Key");
        chckbxAutosubjectkeyidentifier.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                txtSubjectkeyidentifier.setEnabled(!chckbxAutosubjectkeyidentifier.isSelected());
            }
        });

        txtAuthoritykeyidentifier = new JTextField();

        chckbxAutoauthoritykeyidetifier = new JCheckBox("Auto generate from Issuer Public Key");
        chckbxAutoauthoritykeyidetifier.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                txtAuthoritykeyidentifier.setEnabled(!chckbxAutoauthoritykeyidetifier.isSelected());
            }
        });

        lstAllExtensionsModel = new DefaultListModel<>();

        lstUnsupportedExtensions = new JList<String>();

        chckbxCopyUnsupportedExtensions = new JCheckBox("Copy unsupported Extensions");
        chckbxCopyUnsupportedExtensions.setAlignmentY(Component.TOP_ALIGNMENT);
        chckbxCopyUnsupportedExtensions.setSelected(true);

        var topPanel = new JPanel();
        topPanel.setLayout(new MigLayout());
        topPanel.add(new JLabel("SAML Certificates"), "right");
        topPanel.add(new JScrollPane(certificateTree), "height 240!, width 100%, spanx, spany 7, wrap");
        topPanel.add(btnImport, "width 110!, gaptop 20, right, wrap");
        topPanel.add(btnImportCertificateChain, "width 110!, right, wrap");
        topPanel.add(btnExport, "width 110!, right, wrap");
        topPanel.add(btnClone, "width 110!, right, wrap");
        topPanel.add(btnCloneChain, "width 110!, right, wrap");
        topPanel.add(btnDelete, "width 110!, right, top, wrap");
        topPanel.add(new JLabel("Status Log"), "top, right");
        topPanel.add(new JScrollPane(txtStatus), "height 60!, width 100%, spanx, wrap");
        topPanel.add(samlRequestParamNameLabel, "right, gaptop 10");
        topPanel.add(txtSamlRequestParamName, "width 120!");
        topPanel.add(samlResponseParamNameLabel, "gap unrelated");
        topPanel.add(txtSamlResponseParamName, "width 120!");

        var pluginSpecificPanel = new JPanel();
        pluginSpecificPanel.setLayout(new MigLayout());
        pluginSpecificPanel.setBorder(BorderFactory.createTitledBorder("Plugin Specific"));
        pluginSpecificPanel.add(new JLabel("Source"), "right");
        pluginSpecificPanel.add(txtSource, "width 560!, wrap");
        pluginSpecificPanel.add(chckbxPrivateKey, "skip, wrap");
        pluginSpecificPanel.add(new JLabel("Actions"), "right");
        pluginSpecificPanel.add(btnImportPrivateKeyPKCS8, "width 160!, wrap");
        pluginSpecificPanel.add(btnImportPrivateKeyRSA, "width 160!, skip, wrap");
        pluginSpecificPanel.add(btnExportPrivateKeyRSA, "width 160!, skip, wrap");
        pluginSpecificPanel.add(btnSaveAndSelfsign, "width 160!, skip");

        var generalPanel = new JPanel();
        generalPanel.setLayout(new MigLayout());
        generalPanel.setBorder(BorderFactory.createTitledBorder("General"));
        generalPanel.add(new JLabel("Version"), "right");
        generalPanel.add(txtVersion, "width 560!, wrap");
        generalPanel.add(new JLabel("Serial Number (Hex)"), "right");
        generalPanel.add(txtSerialNumber, "width 560!, wrap");
        generalPanel.add(new JLabel("Signature Algorithm"), "right");
        generalPanel.add(txtSignatureAlgorithm, "width 560!, wrap");
        generalPanel.add(new JLabel("Issuer"), "right");
        generalPanel.add(txtIssuer, "width 560!, wrap");
        generalPanel.add(new JLabel("Not Before"), "right");
        generalPanel.add(txtNotBefore, "width 560!, wrap");
        generalPanel.add(new JLabel("Not After"), "right");
        generalPanel.add(txtNotAfter, "width 560!, wrap");
        generalPanel.add(new JLabel("Subject"), "right");
        generalPanel.add(txtSubject, "width 560!, wrap");
        generalPanel.add(new JLabel("Public Key Algorithm"), "right");
        generalPanel.add(txtPublicKeyAlgorithm, "width 560!, wrap");
        generalPanel.add(new JLabel("Key Size"), "right");
        generalPanel.add(txtKeySize, "width 560!, wrap");
        generalPanel.add(new JLabel("Modulus"), "right");
        generalPanel.add(new JScrollPane(txtModulus), "width 560!, height 120!, wrap");
        generalPanel.add(new JLabel("Exponent"), "right");
        generalPanel.add(txtExponent, "width 560!, wrap");
        generalPanel.add(new JLabel("Signature"), "right");
        generalPanel.add(new JScrollPane(txtSignature), "width 560!, height 120!, wrap");

        var supportedExtensionsPanel = new JPanel();
        supportedExtensionsPanel.setLayout(new MigLayout());
        supportedExtensionsPanel.setBorder(BorderFactory.createTitledBorder("Supported Extensions"));
        supportedExtensionsPanel.add(new JLabel("Basic Constraints"), "right");
        supportedExtensionsPanel.add(chckbxCa, "wrap");
        supportedExtensionsPanel.add(new JLabel("Path Limit:"), "skip, wrap");
        supportedExtensionsPanel.add(txtPathLimit, "skip, width 560!, wrap");
        supportedExtensionsPanel.add(chckbxNoPathLimit, "skip, wrap");
        supportedExtensionsPanel.add(chckbxIgnoreBasicConstraints, "skip, wrap");
        supportedExtensionsPanel.add(new JLabel("Key Usage"), "right");
        for (int idx = 0; idx < jbxKeyUsages.size(); idx++) {
            if (idx == 0) {
                supportedExtensionsPanel.add(jbxKeyUsages.get(idx), "wrap");
            } else {
                supportedExtensionsPanel.add(jbxKeyUsages.get(idx), "skip, wrap");
            }
        }
        supportedExtensionsPanel.add(new JLabel("Extended Key Usage"), "right");
        for (int idx = 0; idx < jbxExtendedKeyUsages.size(); idx++) {
            if (idx == 0) {
                supportedExtensionsPanel.add(jbxExtendedKeyUsages.get(idx), "wrap");
            } else {
                supportedExtensionsPanel.add(jbxExtendedKeyUsages.get(idx), "skip, wrap");
            }
        }
        supportedExtensionsPanel.add(new JLabel("Subject Alternative Names"), "right");
        supportedExtensionsPanel.add(new JScrollPane(lstSubjectAlternativeNames), "width 560!");
        supportedExtensionsPanel.add(btnDeletesubjectalternativename, "wrap");
        supportedExtensionsPanel.add(cbbSubjectAlternativeNameType, "right");
        supportedExtensionsPanel.add(txtSubjectAlternativeNameName, "width 560!");
        supportedExtensionsPanel.add(tbnAddSubjectAlternativeName, "wrap");
        supportedExtensionsPanel.add(new JLabel("Issuer Alternative Names"), "right");
        supportedExtensionsPanel.add(new JScrollPane(lstIssuerAlternativeNames), "width 560!");
        supportedExtensionsPanel.add(btnBtndeleteissueralternativename, "wrap");
        supportedExtensionsPanel.add(cbbIssuerAlternativeNameType, "right");
        supportedExtensionsPanel.add(txtIssuerAlternativeNameName, "width 560!");
        supportedExtensionsPanel.add(btnAddissueralternativename, "wrap");
        supportedExtensionsPanel.add(new JLabel("Subject Key Identifier"), "right");
        supportedExtensionsPanel.add(txtSubjectkeyidentifier, "width 560!, wrap");
        supportedExtensionsPanel.add(chckbxAutosubjectkeyidentifier, "skip, wrap");
        supportedExtensionsPanel.add(new JLabel("Authority Key Identifier"), "right");
        supportedExtensionsPanel.add(txtAuthoritykeyidentifier, "width 560!, wrap");
        supportedExtensionsPanel.add(chckbxAutoauthoritykeyidetifier, "skip");

        var unsupportedExtensionsPanel = new JPanel();
        unsupportedExtensionsPanel.setLayout(new MigLayout());
        unsupportedExtensionsPanel.setBorder(BorderFactory.createTitledBorder("Unsupported Extension"));
        unsupportedExtensionsPanel.add(new JScrollPane(lstUnsupportedExtensions), "width 560!, wrap");
        unsupportedExtensionsPanel.add(chckbxCopyUnsupportedExtensions);

        var bottomPanel = new JPanel();
        bottomPanel.setLayout(new MigLayout());
        bottomPanel.add(pluginSpecificPanel, "wrap");
        bottomPanel.add(generalPanel, "wrap");
        bottomPanel.add(supportedExtensionsPanel, "wrap");
        bottomPanel.add(unsupportedExtensionsPanel);

        var scrollableBottomPanel = new JScrollPane(bottomPanel);
        scrollableBottomPanel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY));
        scrollableBottomPanel.getVerticalScrollBar().setUnitIncrement(16);

        this.setLayout(new MigLayout());
        this.add(topPanel, "wrap");
        this.add(scrollableBottomPanel, "width 100%");
    }

    public void setCertificateTabController(CertificateTabController certificateTabController) {
        this.certificateTabController = certificateTabController;
    }

    public void setTxtStatus(String status) {
        txtStatus.setText(status);
    }

    public void setTxtSource(String txtSource) {
        this.txtSource.setText(txtSource);
    }

    public void setChckbxPrivateKey(boolean chckbxPrivateKey) {
        this.chckbxPrivateKey.setSelected(chckbxPrivateKey);
        btnExportPrivateKeyRSA.setEnabled(chckbxPrivateKey);
    }

    public void setSelectedBurpCertificate(BurpCertificate selectedBurpCertificate) {
        this.selectedBurpCertificate = selectedBurpCertificate;
    }

    public boolean getChckbxCopyUnsupportedExtensions() {
        return chckbxCopyUnsupportedExtensions.isSelected();
    }

    public String getTxtSerialNumber() {
        return txtSerialNumber.getText();
    }

    public void setTxtSerialNumber(String txtSerialNumber) {
        this.txtSerialNumber.setText(txtSerialNumber);
    }

    public String getTxtSignatureAlgorithm() {
        return (String) txtSignatureAlgorithm.getSelectedItem();
    }

    public void setTxtSignatureAlgorithm(String txtSignatureAlgorithm) {
        this.txtSignatureAlgorithm.setSelectedItem(txtSignatureAlgorithm);
    }

    public String getTxtIssuer() {
        return txtIssuer.getText();
    }

    public void setTxtIssuer(String txtIssuer) {
        this.txtIssuer.setText(txtIssuer);
    }

    public String getTxtNotBefore() {
        return txtNotBefore.getText();
    }

    public void setTxtNotBefore(String txtNotBefore) {
        this.txtNotBefore.setText(txtNotBefore);
    }

    public String getTxtNotAfter() {
        return txtNotAfter.getText();
    }

    public void setTxtNotAfter(String txtNotAfter) {
        this.txtNotAfter.setText(txtNotAfter);
    }

    public String getTxtSubject() {
        return txtSubject.getText();
    }

    public void setTxtSubject(String txtSubject) {
        this.txtSubject.setText(txtSubject);
    }

    public void setTxtPublicKeyAlgorithm(String txtPublicKeyAlgorithm) {
        this.txtPublicKeyAlgorithm.setSelectedItem(txtPublicKeyAlgorithm);
    }

    public String getTxtKeySize() {
        return txtKeySize.getText();
    }

    public void setTxtKeySize(String txtKeySize) {
        this.txtKeySize.setText(txtKeySize);
    }

    public void setTxtModulus(String txtModulus) {
        this.txtModulus.setText(txtModulus);
    }

    public void setTxtExponent(String txtExponent) {
        this.txtExponent.setText(txtExponent);
    }

    public void setTxtVersion(String txtVersion) {
        this.txtVersion.setText(txtVersion);
    }

    public void setTxtSignature(String signature) {
        this.txtSignature.setText(signature);
    }

    public boolean getChckbxIgnoreBasicConstraints() {
        return chckbxIgnoreBasicConstraints.isSelected();
    }

    public boolean isCa() {
        return chckbxCa.isSelected();
    }

    public void setIsCa(boolean isCa) {
        chckbxCa.setSelected(isCa);
        txtPathLimit.setEnabled(isCa);
        chckbxNoPathLimit.setEnabled(isCa);
    }

    public int getTxtPathLimit() {
        return txtPathLimit.getText().isEmpty() ? 0 : Integer.parseInt(txtPathLimit.getText());
    }

    public void setTxtPathLimit(String pathLimit) {
        if (pathLimit.equals("No Limit")) {
            chckbxNoPathLimit.setSelected(true);
            txtPathLimit.setEnabled(false);
            txtPathLimit.setText("");
        } else {
            chckbxNoPathLimit.setSelected(false);
            txtPathLimit.setEnabled(true);
            txtPathLimit.setText(pathLimit);
        }
    }

    public boolean hasNoPathLimit() {
        return chckbxNoPathLimit.isSelected();
    }

    public void setHasNoPathLimit(boolean hasNoPathLimit) {
        chckbxNoPathLimit.setSelected(hasNoPathLimit);
    }

    public List<String> getKeyUsage() {
        List<String> keyUsage = new LinkedList<>();
        for (JCheckBox j : jbxKeyUsages) {
            if (j.isSelected()) {
                keyUsage.add(j.getText());
            }
        }
        return keyUsage;
    }

    public void setKeyUsage(List<String> keyUsage) {
        for (JCheckBox j : jbxKeyUsages) {
            j.setSelected(false);
            for (String s : keyUsage) {
                if (j.getText().equals(s)) {
                    j.setSelected(true);
                }
            }
        }
    }

    public List<String> getExtendedKeyUsage() {
        List<String> keyUsage = new LinkedList<>();
        for (JCheckBox j : jbxExtendedKeyUsages) {
            if (j.isSelected()) {
                keyUsage.add(j.getText());
            }
        }
        return keyUsage;
    }

    public void setExtendedKeyUsage(List<String> extendedKeyUsage) {
        for (JCheckBox j : jbxExtendedKeyUsages) {
            for (String s : extendedKeyUsage) {
                if (j.getText().equals(s)) {
                    j.setSelected(true);
                }
            }
        }
    }

    public void setSubjectAlternativeNames(List<String> subjectAlternativeNames) {
        lstSubjectAlternativeNamesModel = new DefaultListModel<>();
        for (String s : subjectAlternativeNames) {
            lstSubjectAlternativeNamesModel.addElement(s);
        }
        lstSubjectAlternativeNames.setModel(lstSubjectAlternativeNamesModel);
    }

    public void addSubjectAlternativeNames(String subjectAlternativeName) {
        lstSubjectAlternativeNamesModel.addElement(subjectAlternativeName);
        lstSubjectAlternativeNames.setModel(lstSubjectAlternativeNamesModel);
    }

    public List<String> getSubjectAlternativeNames() {
        List<String> subjectAlternativeNames = new LinkedList<>();
        for (int i = 0; i < lstSubjectAlternativeNamesModel.getSize(); i++) {
            subjectAlternativeNames.add(lstSubjectAlternativeNamesModel.getElementAt(i));
        }
        return subjectAlternativeNames;
    }

    public void setIssuerAlternativeNames(List<String> issuerAlternativeNames) {
        lstIssuerAlternativeNamesModel = new DefaultListModel<>();
        for (String s : issuerAlternativeNames) {
            lstIssuerAlternativeNamesModel.addElement(s);
        }
        lstIssuerAlternativeNames.setModel(lstIssuerAlternativeNamesModel);
    }

    public void addIssuerAlternativeNames(String issuerAlternativeName) {
        lstIssuerAlternativeNamesModel.addElement(issuerAlternativeName);
        lstIssuerAlternativeNames.setModel(lstIssuerAlternativeNamesModel);
    }

    public List<String> getIssuerAlternativeNames() {
        List<String> issuerAlternativeNames = new LinkedList<>();
        for (int i = 0; i < lstIssuerAlternativeNamesModel.getSize(); i++) {
            issuerAlternativeNames.add(lstIssuerAlternativeNamesModel.getElementAt(i));
        }
        return issuerAlternativeNames;
    }

    public void setAuthorityKeyIdentifier(String authorityKeyIdentifier) {
        txtAuthoritykeyidentifier.setText(authorityKeyIdentifier);
    }

    public String getAuthorityKeyIdentifier() {
        return txtAuthoritykeyidentifier.getText();
    }

    public boolean isAutoAuthorityKeyIdentifier() {
        return chckbxAutoauthoritykeyidetifier.isSelected();
    }

    public void setSubjectKeyIdentifier(String subjectKeyIdentifier) {
        txtSubjectkeyidentifier.setText(subjectKeyIdentifier);
    }

    public String getSubjectKeyIdentifier() {
        return txtSubjectkeyidentifier.getText();
    }

    public boolean isAutoSubjectKeyIdentifier() {
        return chckbxAutosubjectkeyidentifier.isSelected();
    }

    public void setCertificateRootNode(DefaultMutableTreeNode rootNode) {
        this.certificateTreeModel.setRoot(rootNode);
    }

    public void setAllExtensions(List<String> allExtensions) {
        lstAllExtensionsModel = new DefaultListModel<>();
        for (String e : allExtensions) {
            lstAllExtensionsModel.addElement(e);
        }
        lstUnsupportedExtensions.setModel(lstAllExtensionsModel);
    }

    public String getSamlRequestParameterName() {
        return txtSamlRequestParamName.getText();
    }

    public String getSamlResponseParameterName() {
        return txtSamlResponseParamName.getText();
    }
}
