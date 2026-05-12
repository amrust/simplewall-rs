#include "promptcoordinator.h"

#include "dbusclient.h"

#include <QDateTime>
#include <QDebug>
#include <QWidget>

static constexpr int kCooldownSeconds = 60;

PromptCoordinator::PromptCoordinator(DbusClient *dbus, QWidget *windowAnchor,
                                     QObject *parent)
    : QObject(parent), m_dbus(dbus), m_anchor(windowAnchor) {
    connect(m_dbus, &DbusClient::connectAttempt,
            this, &PromptCoordinator::onConnectAttempt);
}

void PromptCoordinator::onConnectAttempt(uint pid, const QString &comm,
                                         const QString &ip, ushort port,
                                         const QString &action) {
    // Filter 1: only default-denies need user attention.
    if (action != QStringLiteral("deny")) return;

    // Filter 2: AF_UNIX / AF_NETLINK / etc. don't have routable
    // destinations — the daemon stamps them as "(family=N)". Don't
    // prompt the user for things they can't meaningfully allow.
    if (ip.startsWith(QStringLiteral("(family="))) return;

    // Filter 3: any rule for this comm exists → user already decided
    // about this app (whole-app semantics; matches Win32 amwall).
    if (m_dbus->hasAnyRuleFor(comm)) return;

    // Filter 4: dedup against currently-pending and recently-decided
    // BY COMM ONLY — one prompt per process, regardless of how many
    // different (ip, port) pairs the process tries.
    pruneRecent();
    if (m_pending.contains(comm)) return;
    if (m_decided.contains(comm)) return;

    enqueue({pid, comm, ip, port});
}

void PromptCoordinator::enqueue(const PromptRequest &req) {
    m_pending.insert(req.comm);
    m_queue.enqueue(req);
    notifyCount();
    if (!m_current) processNext();
}

void PromptCoordinator::processNext() {
    if (m_current) return;
    if (m_queue.isEmpty()) {
        notifyCount();
        return;
    }
    m_currentReq = m_queue.dequeue();
    m_current = new ConnectPromptDialog(
        m_currentReq.pid, m_currentReq.comm, m_currentReq.ip, m_currentReq.port,
        nullptr);
    connect(m_current, &ConnectPromptDialog::decided,
            this, &PromptCoordinator::onDecision);

    // Pull the user's attention to amwall: if MainWindow is hidden,
    // we still want them to see the prompt. The dialog itself is
    // top-level + StaysOnTop so it shows above other apps.
    m_current->show();
    m_current->raise();
    m_current->activateWindow();
    notifyCount();
}

void PromptCoordinator::onDecision(ConnectPromptDialog::Decision d) {
    const QString comm = m_currentReq.comm;
    m_pending.remove(comm);

    // Persist a WHOLE-APP wildcard rule, not a per-(comm, ip, port)
    // rule. ip="any" (BPF dest_ip4=0) + port=0 hits step 4 of the
    // BPF wildcard lookup, covering every future IPv4 connect from
    // this comm. Dismiss is no longer a thing — closing the dialog
    // counts as Block (default-deny stance, matches Win32 amwall).
    static const QString kAnyIp = QStringLiteral("any");
    static constexpr ushort kAnyPort = 0;

    switch (d) {
    case ConnectPromptDialog::Allow:
        m_dbus->allow(comm, kAnyIp, kAnyPort);
        break;
    case ConnectPromptDialog::Block:
        m_dbus->deny(comm, kAnyIp, kAnyPort);
        break;
    }
    m_decided.insert(comm, QDateTime::currentDateTime());

    if (m_current) {
        m_current->deleteLater();
        m_current = nullptr;
    }
    processNext();
}

void PromptCoordinator::notifyCount() {
    emit pendingCountChanged(pendingCount());
}

void PromptCoordinator::pruneRecent() {
    QDateTime cutoff = QDateTime::currentDateTime().addSecs(-kCooldownSeconds);
    auto it = m_decided.begin();
    while (it != m_decided.end()) {
        if (it.value() < cutoff) it = m_decided.erase(it);
        else                     ++it;
    }
}
