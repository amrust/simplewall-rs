#include "dashboard.h"

#include "dbusclient.h"
#include "promptcoordinator.h"

#include <QApplication>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPixmap>
#include <QPushButton>
#include <QSizePolicy>
#include <QStyle>
#include <QVBoxLayout>

#ifndef AMWALL_VERSION
#define AMWALL_VERSION "unknown"
#endif

Dashboard::Dashboard(DbusClient *dbus, PromptCoordinator *prompts,
                     QWidget *parent)
    : QWidget(parent), m_dbus(dbus), m_prompts(prompts) {

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 24, 24, 24);
    outer->setSpacing(16);

    // ─── Header ───────────────────────────────────────────────────
    auto *header = new QHBoxLayout;
    header->setSpacing(16);

    auto *iconLabel = new QLabel(this);
    QIcon ico = QIcon::fromTheme(
        "network-firewall",
        style()->standardIcon(QStyle::SP_DriveNetIcon));
    iconLabel->setPixmap(ico.pixmap(48, 48));
    header->addWidget(iconLabel, 0, Qt::AlignTop);

    auto *titleBox = new QVBoxLayout;
    titleBox->setSpacing(2);
    auto *title = new QLabel(QStringLiteral("amwall"), this);
    QFont tf = title->font();
    tf.setPointSize(tf.pointSize() + 6);
    tf.setBold(true);
    title->setFont(tf);
    titleBox->addWidget(title);

    auto *subtitle = new QLabel(
        tr("Per-application firewall — version %1")
            .arg(QString::fromLatin1(AMWALL_VERSION)),
        this);
    // Plain palette text (WCAG-compliant contrast); italic instead of
    // a faded gray for visual hierarchy. palette(mid) fails the AA
    // contrast ratio against window backgrounds on most themes.
    subtitle->setStyleSheet("font-style: italic;");
    titleBox->addWidget(subtitle);
    header->addLayout(titleBox, 1);

    outer->addLayout(header);

    // ─── Daemon group ─────────────────────────────────────────────
    auto *daemonGroup = new QGroupBox(tr("Daemon"), this);
    auto *dlayout = new QFormLayout(daemonGroup);
    dlayout->setLabelAlignment(Qt::AlignRight);
    dlayout->setHorizontalSpacing(16);
    dlayout->setVerticalSpacing(8);

    m_stateLabel = new QLabel(tr("(probing...)"), daemonGroup);
    m_stateLabel->setTextFormat(Qt::RichText);
    dlayout->addRow(tr("State:"), m_stateLabel);

    m_countLabel = new QLabel(QStringLiteral("—"), daemonGroup);
    dlayout->addRow(tr("Rules loaded:"), m_countLabel);

    auto *endpoint = new QLabel(
        QStringLiteral("<code>org.amwall.Daemon1</code> (system bus)"),
        daemonGroup);
    endpoint->setTextFormat(Qt::RichText);
    dlayout->addRow(tr("Endpoint:"), endpoint);

    m_lastLabel = new QLabel(tr("never"), daemonGroup);
    dlayout->addRow(tr("Last refresh:"), m_lastLabel);

    auto *refreshBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_BrowserReload),
        tr("Refresh now"),
        daemonGroup);
    refreshBtn->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
    connect(refreshBtn, &QPushButton::clicked, m_dbus, &DbusClient::refresh);
    dlayout->addRow(QString(), refreshBtn);

    outer->addWidget(daemonGroup);

    // ─── Activity group ───────────────────────────────────────────
    auto *activityGroup = new QGroupBox(tr("Activity"), this);
    auto *alayout = new QFormLayout(activityGroup);
    alayout->setLabelAlignment(Qt::AlignRight);
    alayout->setHorizontalSpacing(16);
    alayout->setVerticalSpacing(8);

    m_pendingLabel = new QLabel(QStringLiteral("0"), activityGroup);
    m_pendingLabel->setTextFormat(Qt::RichText);
    alayout->addRow(tr("Pending prompts:"), m_pendingLabel);

    outer->addWidget(activityGroup);
    outer->addStretch(1);

    connect(m_dbus, &DbusClient::stateChanged,
            this, &Dashboard::onDbusStateChanged);
    connect(m_prompts, &PromptCoordinator::pendingCountChanged,
            this, &Dashboard::onPendingChanged);
    onDbusStateChanged();
    onPendingChanged(m_prompts->pendingCount());
}

void Dashboard::onPendingChanged(int n) {
    if (n == 0) {
        m_pendingLabel->setText(tr("<i>0 (idle)</i>"));
    } else {
        m_pendingLabel->setText(
            tr("<span style='color:#ef6c00; font-weight:bold;'>"
               "%n waiting</span>", "", n));
    }
}

void Dashboard::onDbusStateChanged() {
    if (m_dbus->isReachable()) {
        m_stateLabel->setText(
            tr("<span style='color:#2e7d32; font-weight:bold;'>● Connected</span>"));
        m_countLabel->setText(QString::number(m_dbus->ruleCount()));
    } else {
        QString msg = tr("<span style='color:#c62828; font-weight:bold;'>○ Not reachable</span>");
        QString err = m_dbus->lastError();
        if (!err.isEmpty()) {
            // Italic + small font for hierarchy without the bad
            // contrast of palette(mid). Full text color = WCAG AA.
            msg += QStringLiteral("<br><i style='font-size: small;'>%1</i>")
                       .arg(err.toHtmlEscaped());
        }
        msg += QStringLiteral("<br><i style='font-size: small;'>%1</i>")
                   .arg(tr("start with: <code>sudo systemctl start amwall-daemon</code>"));
        m_stateLabel->setText(msg);
        m_countLabel->setText(QStringLiteral("—"));
    }

    QDateTime ts = m_dbus->lastRefresh();
    m_lastLabel->setText(
        ts.isValid() ? ts.toString("yyyy-MM-dd HH:mm:ss") : tr("never"));
}
