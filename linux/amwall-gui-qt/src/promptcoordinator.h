// PromptCoordinator — receives ConnectAttempt signals from
// DbusClient, filters them down to "this is a process the user
// hasn't decided about yet", queues, and shows one
// ConnectPromptDialog at a time.
//
// Per-comm dedup (matches simplewall/Win32 amwall): one prompt per
// process, not per (process, ip, port). On Allow/Block we persist
// a WHOLE-APP wildcard rule (comm, "any", 0). Future connects from
// the same comm hit the BPF wildcard lookup and never raise a signal
// here.
//
// Filters applied:
//   • action == "deny" only             (allows are silent)
//   • ip is real IPv4 (not "(family=N)" — AF_UNIX etc. don't go
//     through the user's network policy)
//   • !DbusClient::hasAnyRuleFor(comm)  (already in rules.toml)
//   • comm not already pending          (per-comm dedup)
//   • comm not recently decided         (60-sec cooldown — by then
//                                        the daemon has reloaded and
//                                        hasAnyRuleFor will catch it)
//
// Emits pendingCountChanged so the Dashboard widget can show the
// "Pending prompts: N" row. When the queue drains, count goes to 0.

#pragma once

#include <QDateTime>
#include <QHash>
#include <QObject>
#include <QQueue>
#include <QSet>
#include <QString>

#include "connectprompt.h"

class DbusClient;
class QWidget;

struct PromptRequest {
    uint    pid;
    QString comm;
    QString ip;     // first observed destination (informational)
    ushort  port;   // first observed port (informational)
};

class PromptCoordinator : public QObject {
    Q_OBJECT

public:
    PromptCoordinator(DbusClient *dbus, QWidget *windowAnchor,
                      QObject *parent = nullptr);

    int pendingCount() const { return m_queue.size() + (m_current ? 1 : 0); }

signals:
    void pendingCountChanged(int n);

private slots:
    void onConnectAttempt(uint pid, const QString &comm,
                          const QString &ip, ushort port,
                          const QString &action);
    void onDecision(ConnectPromptDialog::Decision d);

private:
    void enqueue(const PromptRequest &req);
    void processNext();
    void notifyCount();
    void pruneRecent();  // expire entries older than 60 sec

    DbusClient *m_dbus;
    QWidget    *m_anchor;  // for raising MainWindow when prompt fires

    QQueue<PromptRequest>     m_queue;
    QSet<QString>             m_pending;   // comms currently in queue or showing
    QHash<QString, QDateTime> m_decided;   // comm → decision time (60-sec cooldown)
    PromptRequest             m_currentReq{};
    ConnectPromptDialog      *m_current = nullptr;
};
