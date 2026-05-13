#include "blocklisttab.h"

#include "dbusclient.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStyle>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

namespace {
constexpr int COL_ENABLED = 0;
constexpr int COL_NAME    = 1;
constexpr int COL_V4      = 2;
constexpr int COL_V6      = 3;
constexpr int COL_DESC    = 4;
}  // namespace

BlocklistTab::BlocklistTab(DbusClient *dbus, QWidget *parent)
    : QWidget(parent), m_dbus(dbus) {

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(8, 8, 8, 8);
    outer->setSpacing(6);

    // ─── Header ───────────────────────────────────────────────────
    auto *header = new QHBoxLayout;
    auto *title = new QLabel(tr("<b>Blocklists</b>"), this);
    title->setTextFormat(Qt::RichText);
    header->addWidget(title);
    m_count = new QLabel(QStringLiteral("(0)"), this);
    header->addWidget(m_count);
    header->addStretch(1);
    auto *refreshBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_BrowserReload),
        tr("Refresh"), this);
    connect(refreshBtn, &QPushButton::clicked, this, &BlocklistTab::refresh);
    header->addWidget(refreshBtn);
    outer->addLayout(header);

    // ─── Table ────────────────────────────────────────────────────
    m_table = new QTableWidget(0, 5, this);
    m_table->setHorizontalHeaderLabels({
        tr("Enabled"), tr("Name"), tr("IPv4"), tr("IPv6"), tr("Description")
    });
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setSortingEnabled(true);
    m_table->verticalHeader()->setVisible(false);
    auto *hh = m_table->horizontalHeader();
    hh->setSectionsClickable(true);
    hh->setSortIndicatorShown(true);
    hh->setSectionResizeMode(QHeaderView::Interactive);
    hh->setStretchLastSection(true);
    m_table->setColumnWidth(COL_ENABLED, 80);
    m_table->setColumnWidth(COL_NAME,    140);
    m_table->setColumnWidth(COL_V4,       80);
    m_table->setColumnWidth(COL_V6,       80);
    // Description stretches.
    outer->addWidget(m_table, 1);

    auto *hint = new QLabel(
        tr("<i style='font-size: small;'>"
           "Toggling Enabled writes <code>/etc/amwall/blocklists.toml</code> "
           "and re-syncs the BPF blocklist maps immediately (polkit-gated). "
           "Blocklist hits override per-app allow rules — a process you've "
           "allowed to connect anywhere will still be denied if it tries "
           "to reach a blocklisted address."
           "</i>"),
        this);
    hint->setTextFormat(Qt::RichText);
    hint->setWordWrap(true);
    outer->addWidget(hint);

    connect(m_table, &QTableWidget::cellChanged,
            this, &BlocklistTab::onItemChanged);
    if (m_dbus) {
        connect(m_dbus, &DbusClient::stateChanged,
                this, &BlocklistTab::refresh);
    }

    // Right-click anywhere in the table → Enable/Disable/Copy popup,
    // same shape as the User Rules tab's context menu (Allow/Block/Copy
    // mapping).
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableWidget::customContextMenuRequested,
            this, &BlocklistTab::onTableContextMenu);

    refresh();
}

void BlocklistTab::refresh() {
    if (!m_dbus) return;
    const QList<BlocklistEntry> lists = m_dbus->blocklistList();

    m_inRefresh = true;
    QSignalBlocker block(m_table);
    m_table->setSortingEnabled(false);
    m_table->setRowCount(lists.size());
    int enabledCount = 0;
    for (int i = 0; i < lists.size(); ++i) {
        const BlocklistEntry &e = lists[i];
        if (e.enabled) ++enabledCount;

        auto *enItem = new QTableWidgetItem;
        enItem->setFlags(enItem->flags() | Qt::ItemIsUserCheckable);
        enItem->setCheckState(e.enabled ? Qt::Checked : Qt::Unchecked);
        enItem->setData(Qt::UserRole, e.name);
        enItem->setText(e.enabled ? tr("On") : tr("Off"));
        enItem->setTextAlignment(Qt::AlignCenter);

        auto *nItem  = new QTableWidgetItem(e.name);
        // Stash the list name on the name cell too so we can recover
        // it from a row index even if the table got sorted.
        nItem->setData(Qt::UserRole, e.name);

        auto *v4Item = new QTableWidgetItem(QString::number(e.v4Count));
        v4Item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        auto *v6Item = new QTableWidgetItem(QString::number(e.v6Count));
        v6Item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        auto *dItem  = new QTableWidgetItem(e.description);
        dItem->setToolTip(e.description);

        m_table->setItem(i, COL_ENABLED, enItem);
        m_table->setItem(i, COL_NAME,    nItem);
        m_table->setItem(i, COL_V4,      v4Item);
        m_table->setItem(i, COL_V6,      v6Item);
        m_table->setItem(i, COL_DESC,    dItem);
    }
    m_table->setSortingEnabled(true);
    m_count->setText(tr("(%1 of %2 enabled)")
                         .arg(enabledCount).arg(lists.size()));
    m_inRefresh = false;
}

void BlocklistTab::onItemChanged(int row, int col) {
    if (m_inRefresh) return;
    if (col != COL_ENABLED) return;
    auto *enItem = m_table->item(row, COL_ENABLED);
    if (!enItem || !m_dbus) return;
    const QString name = enItem->data(Qt::UserRole).toString();
    if (name.isEmpty()) return;
    const bool enabled = (enItem->checkState() == Qt::Checked);
    enItem->setText(enabled ? tr("On") : tr("Off"));
    m_dbus->setBlocklistEnabled(name, enabled);
    // refresh() will fire when DbusClient emits stateChanged from
    // the async-reply handler, so we don't need to manually re-sync
    // here — that would race the daemon's TOML write.
}

void BlocklistTab::onTableContextMenu(const QPoint &pos) {
    // Same shape as UserRulesTab::onTableContextMenu — Enable/Disable
    // mirrors Allow/Block, current state gets a check, clicking the
    // other side fires the existing setBlocklistEnabled path (which
    // is polkit-gated daemon-side). Right-click on empty space → no
    // menu, every item acts on a specific list.
    const QModelIndex idx = m_table->indexAt(pos);
    if (!idx.isValid()) return;

    const int row = idx.row();
    m_table->selectRow(row);

    auto *enItem = m_table->item(row, COL_ENABLED);
    if (!enItem) return;
    const QString name = enItem->data(Qt::UserRole).toString();
    if (name.isEmpty()) return;
    const bool isEnabled = (enItem->checkState() == Qt::Checked);

    QMenu menu(this);

    QAction *enableAct = menu.addAction(tr("&Enable"));
    enableAct->setCheckable(true);
    enableAct->setChecked(isEnabled);
    if (isEnabled) {
        enableAct->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
    }

    QAction *disableAct = menu.addAction(tr("&Disable"));
    disableAct->setCheckable(true);
    disableAct->setChecked(!isEnabled);
    if (!isEnabled) {
        disableAct->setIcon(style()->standardIcon(QStyle::SP_DialogCancelButton));
    }

    menu.addSeparator();

    QAction *copyAct = menu.addAction(
        style()->standardIcon(QStyle::SP_FileIcon),
        tr("&Copy name"));

    QAction *chosen = menu.exec(m_table->viewport()->mapToGlobal(pos));
    if (!chosen) return;

    if (chosen == enableAct) {
        if (!isEnabled) {
            // Drive the same path as the in-row checkbox click —
            // mutate the checkbox state and let onItemChanged handle
            // the D-Bus call so we don't duplicate the polkit flow.
            enItem->setCheckState(Qt::Checked);
        }
    } else if (chosen == disableAct) {
        if (isEnabled) {
            enItem->setCheckState(Qt::Unchecked);
        }
    } else if (chosen == copyAct) {
        QApplication::clipboard()->setText(name);
    }
}
