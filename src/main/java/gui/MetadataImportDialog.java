package gui;

import burp.BurpExtender;
import helpers.MetadataImport;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

/// Discovery dialog for SAML metadata endpoints.
/// Shows a table of probe results; user selects a valid row and clicks Import.
public class MetadataImportDialog {

    private MetadataImportDialog() {}

    public static Optional<String> prompt(Component parent) {
        AtomicReference<String> resultXml = new AtomicReference<>();

        JDialog dialog = new JDialog(
                SwingUtilities.getWindowAncestor(parent),
                "Metadata Import",
                Dialog.ModalityType.APPLICATION_MODAL);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        // --- URL row ---
        var urlField = new JTextField(50);
        var checkBtn = new JButton("Check URL");
        var discoverBtn = new JButton("Discover All");

        var urlRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        urlRow.add(new JLabel("URL:"));
        urlRow.add(urlField);
        urlRow.add(checkBtn);
        urlRow.add(discoverBtn);

        // --- Status / progress ---
        var statusLabel = new JLabel("Enter a base URL and click Discover All, or enter a full metadata URL and click Check URL.");
        var progressBar = new JProgressBar();
        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);

        // --- Results table ---
        List<MetadataImport.ProbeResult> probeResults = new ArrayList<>();
        var tableModel = new DefaultTableModel(new String[]{"URL", "Status"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        var table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(0).setPreferredWidth(480);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.setRowHeight(22);

        // Color valid rows differently
        var renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(
                    JTable t, Object value, boolean selected, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, selected, focus, row, col);
                if (!selected && row < probeResults.size()) {
                    c.setForeground(probeResults.get(row).isValid()
                            ? new Color(0, 180, 80)
                            : t.getForeground());
                } else {
                    c.setForeground(selected ? t.getSelectionForeground() : t.getForeground());
                }
                return c;
            }
        };
        table.getColumnModel().getColumn(0).setCellRenderer(renderer);
        table.getColumnModel().getColumn(1).setCellRenderer(renderer);

        var tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(700, 260));

        // --- Bottom buttons ---
        var importBtn = new JButton("Import Metadata");
        importBtn.setEnabled(false);
        var cancelBtn = new JButton("Cancel");

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                importBtn.setEnabled(row >= 0 && row < probeResults.size() && probeResults.get(row).isValid());
            }
        });

        importBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0 && row < probeResults.size()) {
                resultXml.set(probeResults.get(row).xml());
            }
            dialog.dispose();
        });
        cancelBtn.addActionListener(e -> dialog.dispose());

        // --- Worker tracking so we can cancel on new run ---
        AtomicReference<SwingWorker<?, ?>> activeWorker = new AtomicReference<>();

        // helper: add a result row on EDT
        Runnable resetTable = () -> {
            probeResults.clear();
            tableModel.setRowCount(0);
            importBtn.setEnabled(false);
        };

        // --- Check URL (single probe) ---
        checkBtn.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (url.isEmpty()) { statusLabel.setText("Enter a URL first."); return; }

            SwingWorker<?, ?> prev = activeWorker.get();
            if (prev != null) prev.cancel(true);

            resetTable.run();
            checkBtn.setEnabled(false);
            discoverBtn.setEnabled(false);
            progressBar.setIndeterminate(true);
            progressBar.setVisible(true);
            statusLabel.setText("Checking…");

            var worker = new SwingWorker<MetadataImport.ProbeResult, Void>() {
                @Override
                protected MetadataImport.ProbeResult doInBackground() {
                    var client = java.net.http.HttpClient.newBuilder()
                            .connectTimeout(java.time.Duration.ofSeconds(8))
                            .followRedirects(java.net.http.HttpClient.Redirect.NORMAL)
                            .build();
                    return MetadataImport.probe(url, client);
                }
                @Override
                protected void done() {
                    checkBtn.setEnabled(true);
                    discoverBtn.setEnabled(true);
                    progressBar.setIndeterminate(false);
                    progressBar.setVisible(false);
                    try {
                        MetadataImport.ProbeResult r = get();
                        probeResults.add(r);
                        tableModel.addRow(new Object[]{r.url(), r.status()});
                        statusLabel.setText(r.isValid() ? "Metadata found — select the row and click Import Metadata."
                                : "Response is not valid SAML metadata (" + r.status() + ").");
                        if (r.isValid()) {
                            table.setRowSelectionInterval(0, 0);
                        }
                    } catch (Exception ex) {
                        BurpExtender.api.logging().logToError(ex);
                        statusLabel.setText("Error: " + ex.getMessage());
                    }
                }
            };
            activeWorker.set(worker);
            worker.execute();
        });

        // --- Discover All ---
        discoverBtn.addActionListener(e -> {
            String url = urlField.getText().trim();
            if (url.isEmpty()) { statusLabel.setText("Enter a base URL first (e.g. https://example.com)."); return; }

            SwingWorker<?, ?> prev = activeWorker.get();
            if (prev != null) prev.cancel(true);

            resetTable.run();
            checkBtn.setEnabled(false);
            discoverBtn.setEnabled(false);
            progressBar.setMaximum(MetadataImport.COMMON_PATHS.size());
            progressBar.setValue(0);
            progressBar.setIndeterminate(false);
            progressBar.setVisible(true);
            statusLabel.setText("Probing " + MetadataImport.COMMON_PATHS.size() + " paths…");

            var worker = new SwingWorker<Void, MetadataImport.ProbeResult>() {
                @Override
                protected Void doInBackground() throws InterruptedException {
                    MetadataImport.discover(url, this::publish);
                    return null;
                }
                @Override
                protected void process(List<MetadataImport.ProbeResult> chunks) {
                    for (var r : chunks) {
                        probeResults.add(r);
                        tableModel.addRow(new Object[]{r.url(), r.status()});
                        progressBar.setValue(probeResults.size());
                        statusLabel.setText("Trying: " + r.url());
                        if (r.isValid() && table.getSelectedRow() < 0) {
                            int row = probeResults.size() - 1;
                            table.setRowSelectionInterval(row, row);
                        }
                    }
                }
                @Override
                protected void done() {
                    checkBtn.setEnabled(true);
                    discoverBtn.setEnabled(true);
                    progressBar.setVisible(false);
                    if (isCancelled()) { statusLabel.setText("Cancelled."); return; }
                    long found = probeResults.stream().filter(MetadataImport.ProbeResult::isValid).count();
                    statusLabel.setText(found == 0
                            ? "No metadata endpoints found."
                            : found + " endpoint(s) found — select one and click Import Metadata.");
                    try { get(); } catch (Exception ex) {
                        BurpExtender.api.logging().logToError(ex);
                    }
                }
            };
            activeWorker.set(worker);
            worker.execute();
        });

        // --- Layout ---
        var topPanel = new JPanel(new BorderLayout(0, 6));
        topPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
        topPanel.add(urlRow, BorderLayout.NORTH);
        topPanel.add(progressBar, BorderLayout.CENTER);
        topPanel.add(statusLabel, BorderLayout.SOUTH);

        var centerPanel = new JPanel(new BorderLayout(0, 4));
        centerPanel.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8));
        centerPanel.add(new JLabel("Results:"), BorderLayout.NORTH);
        centerPanel.add(tableScroll, BorderLayout.CENTER);

        var bottomRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 8));
        bottomRow.add(cancelBtn);
        bottomRow.add(importBtn);

        dialog.setLayout(new BorderLayout(0, 6));
        dialog.add(topPanel, BorderLayout.NORTH);
        dialog.add(centerPanel, BorderLayout.CENTER);
        dialog.add(bottomRow, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setLocationRelativeTo(parent);
        dialog.setVisible(true);

        return Optional.ofNullable(resultXml.get());
    }
}
