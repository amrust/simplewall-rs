#include "packetslogtab.h"

#include "dbusclient.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QColor>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QSettings>
#include <QSignalBlocker>
#include <QStyle>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {
constexpr int COL_TIME = 0;
constexpr int COL_ACTION = 1;
constexpr int COL_PROCESS = 2;
constexpr int COL_FAMILY = 3;
constexpr int COL_DEST = 4;

bool isLocalFamily(const QString &ip) {
    return ip.startsWith(QStringLiteral("(family="));
}

QString familyTag(const QString &ip) {
    if (isLocalFamily(ip)) return QStringLiteral("local");
    if (ip.contains(':')) return QStringLiteral("ip6");
    return QStringLiteral("ip4");
}
}  // namespace

PacketsLogTab::PacketsLogTab(DbusClient *dbus, QWidget *parent)
    : QWidget(parent), m_dbus(dbus) {

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(8, 8, 8, 8);
    outer->setSpacing(6);

    // ─── Header bar ───────────────────────────────────────────────
    auto *header = new QHBoxLayout;
    auto *title = new QLabel(tr("<b>Packets log</b>"), this);
    title->setTextFormat(Qt::RichText);
    header->addWidget(title);
    m_count = new QLabel(QStringLiteral("(0)"), this);
    header->addWidget(m_count);
    header->addSpacing(12);

    header->addWidget(new QLabel(tr("Filter:"), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(tr("comm or destination..."));
    m_filter->setClearButtonEnabled(true);
    header->addWidget(m_filter, 1);

    m_showLocal = new QCheckBox(tr("Show local (AF_UNIX)"), this);
    // Default driven by Settings → Notifications → "Show local
    // (AF_UNIX) events in Packets log on startup". Off by default
    // because AF_UNIX is high-volume desktop IPC noise.
    m_showLocal->setChecked(
        QSettings().value("packetslog/showLocal", false).toBool());
    header->addWidget(m_showLocal);

    m_pause = new QPushButton(
        style()->standardIcon(QStyle::SP_MediaPause), tr("Pause"), this);
    m_pause->setCheckable(true);
    header->addWidget(m_pause);

    auto *clear = new QPushButton(
        style()->standardIcon(QStyle::SP_DialogResetButton), tr("Clear"), this);
    header->addWidget(clear);

    outer->addLayout(header);

    // ─── Table ────────────────────────────────────────────────────
    m_table = new QTableWidget(0, 5, this);
    m_table->setHorizontalHeaderLabels({
        tr("Time"), tr("Action"), tr("Process"),
        tr("Family"), tr("Destination")
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(false);  // chronological order matters here
    m_table->verticalHeader()->setVisible(false);
    // Header not sortable on click since rows are time-ordered; all
    // columns user-resizable; Destination stretches to fill.
    auto *hh = m_table->horizontalHeader();
    hh->setSectionsClickable(false);
    hh->setSortIndicatorShown(false);
    hh->setSectionResizeMode(QHeaderView::Interactive);
    hh->setStretchLastSection(true);
    m_table->setColumnWidth(COL_TIME,    90);
    m_table->setColumnWidth(COL_ACTION,  80);
    m_table->setColumnWidth(COL_PROCESS, 220);
    m_table->setColumnWidth(COL_FAMILY,  70);
    // Destination stretches.
    outer->addWidget(m_table, 1);

    auto *hint = new QLabel(
        tr("<i style='font-size: small;'>"
           "Capped at 2000 most-recent events. Local sockets "
           "(AF_UNIX) hidden by default — too noisy. Pause stops "
           "appends without dropping the existing buffer."
           "</i>"),
        this);
    hint->setTextFormat(Qt::RichText);
    hint->setWordWrap(true);
    outer->addWidget(hint);

    // ─── Wiring ───────────────────────────────────────────────────
    connect(m_dbus, &DbusClient::connectAttempt,
            this, &PacketsLogTab::onConnectAttempt);
    connect(clear,   &QPushButton::clicked,
            this, &PacketsLogTab::onClear);
    connect(m_pause, &QPushButton::toggled,
            this, &PacketsLogTab::onTogglePause);
    connect(m_filter, &QLineEdit::textChanged,
            this, &PacketsLogTab::onFilterChanged);
    connect(m_showLocal, &QCheckBox::toggled,
            this, &PacketsLogTab::onShowLocalToggled);
}

void PacketsLogTab::onConnectAttempt(uint pid, const QString &comm,
                                     const QString &ip, ushort port,
                                     const QString &action) {
    if (m_paused) return;
    appendRow(pid, comm, ip, port, action);
}

void PacketsLogTab::appendRow(uint pid, const QString &comm,
                              const QString &ip, ushort port,
                              const QString &action) {
    QSignalBlocker block(m_table);

    const int row = m_table->rowCount();
    m_table->insertRow(row);

    auto *tItem = new QTableWidgetItem(
        QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")));
    auto *aItem = new QTableWidgetItem(action.toUpper());
    if (action == QStringLiteral("allow")) {
        aItem->setForeground(QColor("#2e7d32"));
    } else if (action == QStringLiteral("deny")) {
        aItem->setForeground(QColor("#c62828"));
    }
    auto *pItem = new QTableWidgetItem(
        QStringLiteral("%1 (pid %2)").arg(comm).arg(pid));
    auto *fItem = new QTableWidgetItem(familyTag(ip));
    QString destText;
    if (isLocalFamily(ip)) {
        destText = ip;  // "(family=N)" — keep raw so users see what we saw
    } else if (port == 0) {
        destText = ip;
    } else if (ip.contains(':')) {
        destText = QStringLiteral("[%1]:%2").arg(ip).arg(port);
    } else {
        destText = QStringLiteral("%1:%2").arg(ip).arg(port);
    }
    auto *dItem = new QTableWidgetItem(destText);

    m_table->setItem(row, COL_TIME,    tItem);
    m_table->setItem(row, COL_ACTION,  aItem);
    m_table->setItem(row, COL_PROCESS, pItem);
    m_table->setItem(row, COL_FAMILY,  fItem);
    m_table->setItem(row, COL_DEST,    dItem);

    // Eviction: keep cap by removing the oldest (top of table — we
    // append at the bottom). Pop in a single removeRow rather than
    // shifting cells around.
    while (m_table->rowCount() > m_maxRows) {
        m_table->removeRow(0);
    }

    // Hide if doesn't match current filter/local-visibility state.
    bool hide = false;
    if (!m_showLocal->isChecked() && isLocalFamily(ip)) hide = true;
    if (!hide) {
        const QString needle = m_filter->text().trimmed();
        if (!needle.isEmpty()) {
            const bool hit =
                pItem->text().contains(needle, Qt::CaseInsensitive) ||
                dItem->text().contains(needle, Qt::CaseInsensitive);
            if (!hit) hide = true;
        }
    }
    m_table->setRowHidden(row, hide);

    // Auto-scroll if user hadn't scrolled away.
    auto *vbar = m_table->verticalScrollBar();
    if (vbar && vbar->value() == vbar->maximum()) {
        m_table->scrollToBottom();
    } else if (!vbar) {
        m_table->scrollToBottom();
    }

    m_count->setText(QStringLiteral("(%1)").arg(m_table->rowCount()));
}

void PacketsLogTab::onClear() {
    QSignalBlocker block(m_table);
    m_table->setRowCount(0);
    m_count->setText(QStringLiteral("(0)"));
}

void PacketsLogTab::onTogglePause() {
    m_paused = m_pause->isChecked();
    m_pause->setText(m_paused ? tr("Resume") : tr("Pause"));
    m_pause->setIcon(style()->standardIcon(
        m_paused ? QStyle::SP_MediaPlay : QStyle::SP_MediaPause));
}

void PacketsLogTab::onFilterChanged(const QString &) { applyVisibility(); }
void PacketsLogTab::onShowLocalToggled(bool)        { applyVisibility(); }

void PacketsLogTab::applyVisibility() {
    const QString needle = m_filter->text().trimmed();
    const bool showLocal = m_showLocal->isChecked();
    QSignalBlocker block(m_table);
    for (int r = 0; r < m_table->rowCount(); ++r) {
        auto *fI = m_table->item(r, COL_FAMILY);
        auto *pI = m_table->item(r, COL_PROCESS);
        auto *dI = m_table->item(r, COL_DEST);
        if (!fI || !pI || !dI) continue;
        bool hide = false;
        if (!showLocal && fI->text() == QStringLiteral("local")) hide = true;
        if (!hide && !needle.isEmpty()) {
            const bool hit =
                pI->text().contains(needle, Qt::CaseInsensitive) ||
                dI->text().contains(needle, Qt::CaseInsensitive);
            if (!hit) hide = true;
        }
        m_table->setRowHidden(r, hide);
    }
}
