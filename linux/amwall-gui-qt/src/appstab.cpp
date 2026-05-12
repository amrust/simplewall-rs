#include "appstab.h"

#include "dbusclient.h"

#include <QAbstractItemView>
#include <QAction>
#include <QDir>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHash>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QMenu>
#include <QPushButton>
#include <QSet>
#include <QSettings>
#include <QSignalBlocker>
#include <QStyle>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <algorithm>

namespace {
constexpr int COL_NAME  = 0;
constexpr int COL_COMM  = 1;
constexpr int COL_RULES = 2;
constexpr int COL_EXEC  = 3;

struct DesktopApp {
    QString name;
    QString exec;       // raw Exec= value, %-codes left in for display
    QString iconName;   // resolved via QIcon::fromTheme
    QString comm;       // first 15 chars of basename(first-word(Exec))
};

// Strip the first word of an Exec= value (the actual command, before
// args/field-codes), drop env-var prefixes like "env FOO=bar firefox",
// take the basename, and truncate to TASK_COMM_LEN-1 = 15. That's
// what bpf_get_current_comm() / task->group_leader->comm returns
// after a fork+exec — matching the BPF map key.
QString commFromExec(const QString &exec) {
    if (exec.isEmpty()) return {};
    QString first = exec.section(' ', 0, 0).trimmed();
    // skip `env FOO=bar firefox` style — keep taking next word until
    // it's not VAR=value, then that's the binary.
    int wordIdx = 0;
    while (first == QStringLiteral("env") || first.contains('=')) {
        ++wordIdx;
        first = exec.section(' ', wordIdx, wordIdx).trimmed();
        if (first.isEmpty()) return {};
        if (wordIdx > 4) break;  // bail
    }
    if (first.startsWith('"') && first.endsWith('"') && first.size() >= 2) {
        first = first.mid(1, first.size() - 2);
    }
    QString base = first.section('/', -1);
    return base.left(15);
}

QStringList desktopDirs() {
    QStringList dirs = {
        QStringLiteral("/usr/share/applications"),
        QStringLiteral("/usr/local/share/applications"),
        QDir::homePath() + QStringLiteral("/.local/share/applications"),
        QStringLiteral("/var/lib/flatpak/exports/share/applications"),
        QDir::homePath() + QStringLiteral("/.local/share/flatpak/exports/share/applications"),
        QStringLiteral("/var/lib/snapd/desktop/applications"),
    };
    return dirs;
}

QList<DesktopApp> scanDesktopApps() {
    QList<DesktopApp> apps;
    QSet<QString> seenNames;  // dedup display name across dirs
    for (const QString &dirPath : desktopDirs()) {
        QDir dir(dirPath);
        if (!dir.exists()) continue;
        const QStringList files = dir.entryList(
            QStringList{QStringLiteral("*.desktop")}, QDir::Files);
        for (const QString &f : files) {
            QSettings ini(dir.absoluteFilePath(f), QSettings::IniFormat);
            ini.beginGroup(QStringLiteral("Desktop Entry"));
            if (ini.value(QStringLiteral("NoDisplay")).toBool() ||
                ini.value(QStringLiteral("Hidden")).toBool()) {
                ini.endGroup();
                continue;
            }
            const QString type = ini.value(QStringLiteral("Type")).toString();
            if (!type.isEmpty() && type != QStringLiteral("Application")) {
                ini.endGroup();
                continue;
            }
            DesktopApp a;
            a.name     = ini.value(QStringLiteral("Name")).toString();
            a.exec     = ini.value(QStringLiteral("Exec")).toString();
            a.iconName = ini.value(QStringLiteral("Icon")).toString();
            ini.endGroup();
            if (a.name.isEmpty() || a.exec.isEmpty()) continue;
            a.comm = commFromExec(a.exec);
            if (a.comm.isEmpty()) continue;
            // Dedup by (name, comm): same app installed twice across
            // /usr and ~/.local shouldn't appear as two rows.
            const QString key = a.name + QStringLiteral("\x01") + a.comm;
            if (seenNames.contains(key)) continue;
            seenNames.insert(key);
            apps.append(a);
        }
    }
    std::sort(apps.begin(), apps.end(), [](const DesktopApp &l,
                                           const DesktopApp &r) {
        return l.name.localeAwareCompare(r.name) < 0;
    });
    return apps;
}
}  // namespace

AppsTab::AppsTab(DbusClient *dbus, QWidget *parent)
    : QWidget(parent), m_dbus(dbus) {

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(8, 8, 8, 8);
    outer->setSpacing(6);

    // ─── Header bar ───────────────────────────────────────────────
    auto *header = new QHBoxLayout;
    auto *title = new QLabel(tr("<b>Apps</b>"), this);
    title->setTextFormat(Qt::RichText);
    header->addWidget(title);
    m_count = new QLabel(QStringLiteral("(0)"), this);
    header->addWidget(m_count);
    header->addSpacing(12);

    header->addWidget(new QLabel(tr("Filter:"), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(tr("name, comm, or exec..."));
    m_filter->setClearButtonEnabled(true);
    header->addWidget(m_filter, 1);

    auto *refresh = new QPushButton(
        style()->standardIcon(QStyle::SP_BrowserReload), tr("Rescan"), this);
    header->addWidget(refresh);

    outer->addLayout(header);

    // ─── Table ────────────────────────────────────────────────────
    m_table = new QTableWidget(0, 4, this);
    m_table->setHorizontalHeaderLabels({
        tr("Name"), tr("Process (comm)"), tr("Rules"), tr("Exec")
    });
    // Header tooltip explains the comm column matches the kernel's
    // 15-char TASK_COMM_NAME — same key the BPF rule map uses, so
    // the user knows what "Process (comm)" semantically is.
    m_table->horizontalHeaderItem(COL_COMM)->setToolTip(
        tr("Kernel TASK_COMM_NAME — the 15-char basename of the\n"
           "process binary that the BPF rule map matches against."));
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSortingEnabled(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->verticalHeader()->setVisible(false);
    // All Interactive (any divider draggable). Exec is last and
    // stretches to fill — that's the data-heavy column.
    auto *hh = m_table->horizontalHeader();
    hh->setSectionsClickable(true);
    hh->setSortIndicatorShown(true);
    hh->setSectionResizeMode(QHeaderView::Interactive);
    hh->setStretchLastSection(true);
    m_table->setColumnWidth(COL_NAME,  240);
    m_table->setColumnWidth(COL_COMM,  160);
    m_table->setColumnWidth(COL_RULES,  60);
    // Exec stretches.
    outer->addWidget(m_table, 1);

    auto *hint = new QLabel(
        tr("<i style='font-size: small;'>"
           "Right-click an app to add an allow/deny rule for its comm "
           "or jump to it in the User Rules tab. comm is the kernel's "
           "15-char TASK_COMM_NAME — the same key the BPF map uses, "
           "so the rule you create here matches what the daemon sees."
           "</i>"),
        this);
    hint->setTextFormat(Qt::RichText);
    hint->setWordWrap(true);
    outer->addWidget(hint);

    // ─── Wiring ───────────────────────────────────────────────────
    connect(refresh, &QPushButton::clicked,
            this, &AppsTab::refreshApps);
    connect(m_table, &QWidget::customContextMenuRequested,
            this, &AppsTab::onContextMenu);
    connect(m_filter, &QLineEdit::textChanged,
            this, &AppsTab::onFilterChanged);
    if (m_dbus) {
        connect(m_dbus, &DbusClient::stateChanged,
                this, &AppsTab::refreshRuleCounts);
    }

    refreshApps();
}

void AppsTab::refreshApps() {
    const QList<DesktopApp> apps = scanDesktopApps();

    // Count rules per comm. One pass over the rule list.
    QHash<QString, int> counts;
    if (m_dbus) {
        for (const RuleEntry &r : m_dbus->rules()) {
            ++counts[r.comm];
        }
    }

    QSignalBlocker block(m_table);
    m_table->setSortingEnabled(false);
    m_table->setRowCount(apps.size());
    for (int i = 0; i < apps.size(); ++i) {
        const DesktopApp &a = apps[i];
        auto *nItem = new QTableWidgetItem(a.name);
        if (!a.iconName.isEmpty()) {
            QIcon ic = QIcon::fromTheme(a.iconName);
            if (!ic.isNull()) nItem->setIcon(ic);
        }
        auto *cItem = new QTableWidgetItem(a.comm);
        auto *eItem = new QTableWidgetItem(a.exec);
        eItem->setToolTip(a.exec);
        const int n = counts.value(a.comm, 0);
        auto *rItem = new QTableWidgetItem(QString::number(n));
        // Right-aligned numeric cell, dim when zero (no rules yet).
        rItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        if (n == 0) rItem->setForeground(palette().color(QPalette::Disabled,
                                                          QPalette::Text));
        m_table->setItem(i, COL_NAME,  nItem);
        m_table->setItem(i, COL_COMM,  cItem);
        m_table->setItem(i, COL_EXEC,  eItem);
        m_table->setItem(i, COL_RULES, rItem);
    }
    m_table->setSortingEnabled(true);
    m_count->setText(QStringLiteral("(%1)").arg(apps.size()));

    // Re-apply filter visibility after rebuild.
    onFilterChanged(m_filter->text());
}

void AppsTab::refreshRuleCounts() {
    // Cheap: same .desktop list, just recompute rule counts column.
    if (!m_dbus) return;
    QHash<QString, int> counts;
    for (const RuleEntry &r : m_dbus->rules()) {
        ++counts[r.comm];
    }
    QSignalBlocker block(m_table);
    for (int r = 0; r < m_table->rowCount(); ++r) {
        auto *commItem = m_table->item(r, COL_COMM);
        auto *cntItem  = m_table->item(r, COL_RULES);
        if (!commItem || !cntItem) continue;
        const int n = counts.value(commItem->text(), 0);
        cntItem->setText(QString::number(n));
        if (n == 0) {
            cntItem->setForeground(palette().color(QPalette::Disabled,
                                                    QPalette::Text));
        } else {
            cntItem->setForeground(palette().color(QPalette::Active,
                                                    QPalette::Text));
        }
    }
}

void AppsTab::onContextMenu(const QPoint &pos) {
    const int row = m_table->rowAt(pos.y());
    if (row < 0) return;
    auto *commItem = m_table->item(row, COL_COMM);
    auto *nameItem = m_table->item(row, COL_NAME);
    if (!commItem) return;
    const QString comm = commItem->text();
    const QString name = nameItem ? nameItem->text() : comm;

    QMenu menu(this);
    auto *allow = menu.addAction(
        style()->standardIcon(QStyle::SP_DialogApplyButton),
        tr("Allow \"%1\" (writes wildcard rule)").arg(name));
    auto *deny  = menu.addAction(
        style()->standardIcon(QStyle::SP_DialogNoButton),
        tr("Block \"%1\"").arg(name));
    menu.addSeparator();
    auto *jump  = menu.addAction(
        style()->standardIcon(QStyle::SP_FileDialogContentsView),
        tr("Show in User Rules"));

    QAction *picked = menu.exec(m_table->viewport()->mapToGlobal(pos));
    if (!picked || !m_dbus) return;
    if (picked == allow) {
        m_dbus->allow(comm, QStringLiteral("any"), 0);
    } else if (picked == deny) {
        m_dbus->deny(comm, QStringLiteral("any"), 0);
    } else if (picked == jump) {
        emit showInRulesRequested(comm);
    }
}

void AppsTab::onFilterChanged(const QString &text) {
    const QString needle = text.trimmed();
    QSignalBlocker block(m_table);
    for (int r = 0; r < m_table->rowCount(); ++r) {
        auto *n = m_table->item(r, COL_NAME);
        auto *c = m_table->item(r, COL_COMM);
        auto *e = m_table->item(r, COL_EXEC);
        if (!n || !c || !e) continue;
        bool hide = false;
        if (!needle.isEmpty()) {
            const bool hit =
                n->text().contains(needle, Qt::CaseInsensitive) ||
                c->text().contains(needle, Qt::CaseInsensitive) ||
                e->text().contains(needle, Qt::CaseInsensitive);
            if (!hit) hide = true;
        }
        m_table->setRowHidden(r, hide);
    }
}
