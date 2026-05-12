// Dashboard — central widget shown in MainWindow until 6.4 replaces
// it with the tabbed app/rules/connections view. Renders DbusClient
// state + PromptCoordinator state as a polished status panel:
//   • header with theme icon + product name + version
//   • daemon group: state, rule count, endpoint, refresh button
//   • activity group: pending prompts (live count from coordinator)
// Updates itself on DbusClient::stateChanged + pendingCountChanged.

#pragma once

#include <QWidget>

class QLabel;
class DbusClient;
class PromptCoordinator;

class Dashboard : public QWidget {
    Q_OBJECT

public:
    Dashboard(DbusClient *dbus, PromptCoordinator *prompts,
              QWidget *parent = nullptr);

private slots:
    void onDbusStateChanged();
    void onPendingChanged(int n);

private:
    DbusClient        *m_dbus;
    PromptCoordinator *m_prompts;
    QLabel            *m_stateLabel = nullptr;
    QLabel            *m_countLabel = nullptr;
    QLabel            *m_lastLabel  = nullptr;
    QLabel            *m_pendingLabel = nullptr;
};
