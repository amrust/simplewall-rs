// AppsTab — Phase 6.7. Lists installed desktop apps drawn from
// /usr/share/applications, ~/.local/share/applications, and the
// usual flatpak/snap locations. For each entry we extract Name,
// Exec, Icon, derive the kernel comm (first 15 chars of basename(Exec)),
// and cross-reference DbusClient::rules() to show how many rules
// already exist for that comm.
//
// Right-clicking a row offers "Allow this app" / "Block this app"
// (writes a wildcard rule for the comm) and "Show in User Rules"
// (switches to the User Rules tab — wired via showInRules signal).
//
// Auto-rescans the .desktop files lazily — only on first show and
// when the user clicks Refresh, since .desktop entries change at
// install-package cadence, not connection cadence.

#pragma once

#include <QWidget>

class DbusClient;
class QLabel;
class QLineEdit;
class QTableWidget;

class AppsTab : public QWidget {
    Q_OBJECT

public:
    explicit AppsTab(DbusClient *dbus, QWidget *parent = nullptr);

signals:
    void showInRulesRequested(const QString &comm);

public slots:
    void refreshApps();         // re-scan .desktop files (manual button)
    void refreshRuleCounts();   // re-bind rule counts after stateChanged

private slots:
    void onContextMenu(const QPoint &pos);
    void onFilterChanged(const QString &text);

private:
    DbusClient   *m_dbus  = nullptr;
    QTableWidget *m_table = nullptr;
    QLabel       *m_count = nullptr;
    QLineEdit    *m_filter = nullptr;
};
