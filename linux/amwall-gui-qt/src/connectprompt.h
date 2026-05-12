// ConnectPromptDialog — modeless top-level dialog shown when an
// unknown process tries to connect (default-deny in BPF). User
// picks Allow or Block — both persist a WHOLE-APP wildcard rule
// (comm, "any", 0) so subsequent connects from the same comm are
// silently allowed/denied. Closing the window via the title-bar X
// is treated as Block (matches simplewall/Win32 amwall: anything
// not explicitly allowed is denied).
//
// Top-level (no parent), Qt::Window, WindowStaysOnTopHint so it
// doesn't get buried under MainWindow or other apps. Centred on
// the primary screen by Qt default.
//
// PromptCoordinator owns the dialog lifecycle.

#pragma once

#include <QDialog>
#include <QString>

class QLabel;

class ConnectPromptDialog : public QDialog {
    Q_OBJECT

public:
    enum Decision { Allow, Block };

    ConnectPromptDialog(uint pid,
                        const QString &comm,
                        const QString &ip,
                        ushort port,
                        QWidget *parent = nullptr);

signals:
    void decided(Decision d);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    bool m_emitted = false;
    void emitOnce(Decision d);
};
