// RuleEditorDialog — modal dialog for adding or editing a rule.
//
// Two modes selected by the constructor:
//   • Add mode (existing == nullptr): all fields editable. Use to
//     create a brand-new rule. (comm, ip, port) is the daemon's
//     unique key — submitting an existing key upserts.
//   • Edit mode (existing != nullptr): only the action is editable.
//     Process / IP / Port are shown read-only. To change those, the
//     user deletes the rule and adds a new one — this avoids the
//     orphan-state risk of "delete-then-add" (no daemon Update RPC).

#pragma once

#include <QDialog>

#include "dbusclient.h"   // for RuleEntry

class QComboBox;
class QLineEdit;
class QSpinBox;
class QDialogButtonBox;

class RuleEditorDialog : public QDialog {
    Q_OBJECT

public:
    explicit RuleEditorDialog(const RuleEntry *existing = nullptr,
                              QWidget *parent = nullptr);

    QString comm()   const;
    QString ip()     const;
    ushort  port()   const;
    QString action() const;   // "allow" | "deny"

private slots:
    void validateAndAccept();

private:
    bool m_isEdit;
    QLineEdit        *m_comm = nullptr;
    QComboBox        *m_action = nullptr;
    QLineEdit        *m_ip = nullptr;
    QSpinBox         *m_port = nullptr;
    QDialogButtonBox *m_buttons = nullptr;
};
