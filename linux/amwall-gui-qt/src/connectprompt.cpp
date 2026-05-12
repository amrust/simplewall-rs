#include "connectprompt.h"

#include <QApplication>
#include <QByteArray>
#include <QCloseEvent>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPushButton>
#include <QSettings>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

namespace {

// Resolve /proc/<pid>/exe — symlink to the actual binary. Returns
// empty string if the process has already exited or perms deny us.
// Note we read this in the GUI process (running as 'somebody'); a
// root-owned binary's exe symlink is still readable by anyone with
// /proc access since the symlink target itself isn't dereferenced
// — only the link string matters.
QString resolveExe(uint pid) {
    QFileInfo link(QStringLiteral("/proc/%1/exe").arg(pid));
    if (!link.isSymLink()) return {};
    return link.symLinkTarget();
}

// /proc/<pid>/cmdline is argv joined by NUL bytes, trailing NUL.
// Replace NULs with spaces for display; truncate at 200 chars so a
// pathological cmdline doesn't blow up the dialog width.
QString resolveCmdline(uint pid) {
    QFile f(QStringLiteral("/proc/%1/cmdline").arg(pid));
    if (!f.open(QIODevice::ReadOnly)) return {};
    QByteArray bytes = f.readAll();
    if (bytes.isEmpty()) return {};
    if (bytes.endsWith('\0')) bytes.chop(1);
    bytes.replace('\0', ' ');
    QString s = QString::fromLocal8Bit(bytes);
    if (s.size() > 200) s = s.left(197) + QStringLiteral("...");
    return s;
}

}  // namespace

ConnectPromptDialog::ConnectPromptDialog(uint pid,
                                         const QString &comm,
                                         const QString &ip,
                                         ushort port,
                                         QWidget *parent)
    : QDialog(parent,
              Qt::Window
              | Qt::WindowTitleHint
              | Qt::WindowCloseButtonHint
              | Qt::WindowStaysOnTopHint) {
    setWindowTitle(tr("Connection request — amwall"));
    setModal(false);
    setMinimumWidth(420);

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(20, 20, 20, 20);
    outer->setSpacing(14);

    // ─── Header row: icon + headline ──────────────────────────────
    auto *header = new QHBoxLayout;
    header->setSpacing(14);

    auto *iconLabel = new QLabel(this);
    QIcon ico = style()->standardIcon(QStyle::SP_MessageBoxQuestion);
    iconLabel->setPixmap(ico.pixmap(40, 40));
    header->addWidget(iconLabel, 0, Qt::AlignTop);

    // "Process" prefix disambiguates from same-name protocols/services
    // (e.g. comm="http" reads as the HTTP protocol without the noun).
    // The kernel's TASK_COMM_NAME is the basename of the executable
    // truncated to 15 chars — see /proc/<pid>/comm.
    auto *headline = new QLabel(
        tr("Process <b>%1</b> wants to connect.").arg(comm.toHtmlEscaped()),
        this);
    headline->setTextFormat(Qt::RichText);
    headline->setWordWrap(true);
    QFont hf = headline->font();
    hf.setPointSize(hf.pointSize() + 1);
    headline->setFont(hf);
    header->addWidget(headline, 1);

    outer->addLayout(header);

    // ─── Detail rows ──────────────────────────────────────────────
    auto *details = new QFormLayout;
    details->setLabelAlignment(Qt::AlignRight);
    details->setHorizontalSpacing(12);
    details->setVerticalSpacing(4);

    details->addRow(tr("Process:"),
        new QLabel(QStringLiteral("<code>%1</code> (pid %2)")
                       .arg(comm.toHtmlEscaped())
                       .arg(pid), this));

    // /proc/<pid>/exe and cmdline disambiguate the truncated 15-char
    // TASK_COMM_NAME — e.g. comm="http" could be HTTPie at
    // /usr/local/bin/http, /usr/bin/http (a shell wrapper), or anything
    // else a user installed. Race window: the process may have exited
    // between the BPF event and the GUI handling it; rows are omitted
    // when /proc is empty rather than showing misleading placeholders.
    const QString exePath = resolveExe(pid);
    if (!exePath.isEmpty()) {
        auto *exeLabel = new QLabel(
            QStringLiteral("<code>%1</code>").arg(exePath.toHtmlEscaped()), this);
        exeLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        exeLabel->setWordWrap(true);
        details->addRow(tr("Binary:"), exeLabel);
    }

    const QString cmdline = resolveCmdline(pid);
    if (!cmdline.isEmpty()) {
        auto *cmdLabel = new QLabel(
            QStringLiteral("<code>%1</code>").arg(cmdline.toHtmlEscaped()), this);
        cmdLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        cmdLabel->setWordWrap(true);
        details->addRow(tr("Command:"), cmdLabel);
    }

    details->addRow(tr("First destination:"),
        new QLabel(QStringLiteral("<code>%1:%2</code>")
                       .arg(ip.toHtmlEscaped())
                       .arg(port), this));
    details->addRow(tr("Default action:"),
        new QLabel(tr("<span style='color:#c62828;'>blocked</span> (no rule)"), this));

    outer->addLayout(details);

    // Italic + small for visual hierarchy; full text color for WCAG
    // contrast. Wording reflects whole-app semantics: Allow / Block
    // persist a wildcard rule for the comm, not just this one
    // destination. Closing the window = Block (default-deny stance).
    auto *hint = new QLabel(
        tr("<i style='font-size: small;'>"
           "Allow lets <b>%1</b> connect to anywhere. Block silently "
           "denies all of its connections. Closing this window also "
           "blocks. Use the User Rules tab later to fine-tune by "
           "destination or port.</i>")
            .arg(comm.toHtmlEscaped()),
        this);
    hint->setTextFormat(Qt::RichText);
    hint->setWordWrap(true);
    outer->addWidget(hint);

    // ─── Buttons ──────────────────────────────────────────────────
    auto *buttons = new QHBoxLayout;
    buttons->addStretch(1);

    auto *blockBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_DialogNoButton),
        tr("&Block"), this);
    auto *allowBtn = new QPushButton(
        style()->standardIcon(QStyle::SP_DialogApplyButton),
        tr("&Allow"), this);
    allowBtn->setDefault(true);

    buttons->addWidget(blockBtn);
    buttons->addWidget(allowBtn);
    outer->addLayout(buttons);

    connect(allowBtn, &QPushButton::clicked, this, [this]{ emitOnce(Allow); });
    connect(blockBtn, &QPushButton::clicked, this, [this]{ emitOnce(Block); });

    // Settings → notifications/autoBlockSec: if non-zero, auto-Block
    // after N seconds of no user click. Matches simplewall's
    // "Notifications timeout". Safe default action since amwall is
    // default-deny — picking Block on inactivity is the safe choice.
    const int autoBlockSec = QSettings().value(
        QStringLiteral("notifications/autoBlockSec"), 0).toInt();
    if (autoBlockSec > 0) {
        QTimer::singleShot(autoBlockSec * 1000, this, [this]{
            if (!m_emitted) emitOnce(Block);
        });
    }
}

void ConnectPromptDialog::emitOnce(Decision d) {
    if (m_emitted) return;
    m_emitted = true;
    emit decided(d);
    close();
}

void ConnectPromptDialog::closeEvent(QCloseEvent *event) {
    // Window close (X button) counts as Block — anything not
    // explicitly allowed is denied (matches simplewall/Win32 amwall:
    // there's no "ignore this and re-prompt" path). Guard with
    // m_emitted so we don't double-fire when emitOnce already
    // called close().
    if (!m_emitted) {
        m_emitted = true;
        emit decided(Block);
    }
    event->accept();
}
