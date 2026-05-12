// BlocklistTab — Phase 6.9. Front-end for the daemon's blocklist API
// (BlocklistList / BlocklistSetEnabled). One row per .txt under
// /usr/share/amwall/blocklists/. Checkbox in the Enabled column
// triggers a polkit-gated D-Bus call that re-syncs the BPF maps;
// the next stateChanged refresh re-reads the list to confirm.
//
// Blocklist hits are HARD denies — they fire before per-comm rules,
// so a user "Allow firefox to anywhere" cannot bypass a blocklist
// entry that covers the destination IP. Matches simplewall's
// IDC_RULES_BLOCKLIST semantic.

#pragma once

#include <QWidget>

class DbusClient;
class QLabel;
class QTableWidget;

class BlocklistTab : public QWidget {
    Q_OBJECT

public:
    explicit BlocklistTab(DbusClient *dbus, QWidget *parent = nullptr);

public slots:
    void refresh();

private slots:
    void onItemChanged(int row, int col);

private:
    DbusClient   *m_dbus  = nullptr;
    QTableWidget *m_table = nullptr;
    QLabel       *m_count = nullptr;
    bool          m_inRefresh = false;  // suppress itemChanged during refresh
};
