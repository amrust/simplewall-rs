// PacketsLogTab — Phase 6.6. Rolling history of every BPF
// ConnectAttempt event the daemon emits, viewed via the existing
// DbusClient::connectAttempt Qt signal (already in use by the
// prompt coordinator, so this tab is purely additive).
//
// Capped at 2000 rows; oldest row evicted on overflow. Pause toggles
// stop appends without dropping the buffer. Filter line edit is a
// case-insensitive substring match over Process/Destination cells.
//
// Local (AF_UNIX, ip="(family=1)") events are hidden by default —
// every desktop process emits hundreds of them and they'd drown out
// real network activity. The "Show local" checkbox flips this.

#pragma once

#include <QWidget>

class DbusClient;
class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class PacketsLogTab : public QWidget {
    Q_OBJECT

public:
    explicit PacketsLogTab(DbusClient *dbus, QWidget *parent = nullptr);

public slots:
    void onConnectAttempt(uint pid, const QString &comm,
                          const QString &ip, ushort port,
                          const QString &action);
    void onClear();
    void onTogglePause();
    void onFilterChanged(const QString &text);
    void onShowLocalToggled(bool on);

private:
    void applyVisibility();
    void appendRow(uint pid, const QString &comm,
                   const QString &ip, ushort port,
                   const QString &action);

    DbusClient   *m_dbus    = nullptr;
    QTableWidget *m_table   = nullptr;
    QLabel       *m_count   = nullptr;
    QPushButton  *m_pause   = nullptr;
    QLineEdit    *m_filter  = nullptr;
    QCheckBox    *m_showLocal = nullptr;
    bool          m_paused  = false;
    int           m_maxRows = 2000;
};
