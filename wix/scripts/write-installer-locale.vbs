' amwall — MSI custom action: write install-time LCID to per-user file.
' Copyright (C) 2026  amwall contributors. Licensed GPL-3.0-or-later.
'
' Runs as the installing user (Execute=deferred + Impersonate=yes) so
' %APPDATA% resolves to the user's Roaming AppData even though the MSI
' itself is per-machine and runs elevated. Writes the resolved
' [ProductLanguage] LCID (passed in via CustomActionData) to
' %APPDATA%\amwall\installerlocale.txt as plain decimal text.
'
' amwall on next startup reads this file and, if its content differs
' from the LCID it last applied (settings.install_lcid_seen), overrides
' settings.language with the matching culture so the user lands in the
' language they installed in. The mechanism works even when upgrading
' from a pre-multilingual MSI that left a stale `language=en` in
' settings.txt — because the app's "last seen" field starts at 0 and
' any non-zero file content triggers the override.
'
' Errors are swallowed (On Error Resume Next + Return="ignore" on the
' CA) so a failed write never blocks installation. amwall just falls
' back to its existing system-locale auto-detect path in that case.

Function WriteInstallerLocale()
    On Error Resume Next

    Dim lcid
    lcid = Session.Property("CustomActionData")
    If lcid = "" Then
        WriteInstallerLocale = 0
        Exit Function
    End If

    Dim shell, fso, appData, dir, filePath, file
    Set shell = CreateObject("WScript.Shell")
    Set fso = CreateObject("Scripting.FileSystemObject")

    appData = shell.ExpandEnvironmentStrings("%APPDATA%")
    dir = fso.BuildPath(appData, "amwall")
    If Not fso.FolderExists(dir) Then
        fso.CreateFolder(dir)
    End If
    filePath = fso.BuildPath(dir, "installerlocale.txt")

    Set file = fso.CreateTextFile(filePath, True)
    file.WriteLine(lcid)
    file.Close

    WriteInstallerLocale = 0
End Function
