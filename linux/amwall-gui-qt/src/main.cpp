// amwall-gui — entry point (Phase 6.1 foundation + 6.2 dashboard).
//
// Hybrid C++/Qt6 GUI: talks to amwall-daemon over the existing
// org.amwall.Daemon1 system-bus interface (same wire as
// amwall-cli --dbus). Replaces the Phase 3.5 Iced popup.
//
// Tray-resident: closing the window hides instead of quitting; the
// tray icon's right-click → Quit is the real exit path.
//
// CLI flags handled before QApplication is constructed (so --version
// / --help work in headless environments without a Qt display):
//   --version, -V    print version and exit
//   --help,    -h    print usage and exit

#include <QApplication>
#include <QDebug>
#include <QLibraryInfo>
#include <QLocale>
#include <QSettings>
#include <QTranslator>

#include <cstdio>
#include <cstring>

#include "mainwindow.h"

#ifndef AMWALL_VERSION
#define AMWALL_VERSION "unknown"
#endif

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (std::strcmp(a, "--version") == 0 || std::strcmp(a, "-V") == 0) {
            std::printf("amwall-gui %s\n", AMWALL_VERSION);
            return 0;
        }
        if (std::strcmp(a, "--help") == 0 || std::strcmp(a, "-h") == 0) {
            std::printf(
                "amwall-gui — Qt6 front-end for amwall-daemon\n"
                "\n"
                "Usage: amwall-gui [OPTIONS]\n"
                "\n"
                "Options:\n"
                "  -V, --version   print version and exit\n"
                "  -h, --help      show this message and exit\n"
                "\n"
                "Talks to org.amwall.Daemon1 on the system bus. The\n"
                "daemon must be running (sudo systemctl start amwall-daemon).\n");
            return 0;
        }
    }

    QApplication app(argc, argv);
    app.setApplicationName("amwall");
    app.setApplicationDisplayName("amwall");
    app.setApplicationVersion(AMWALL_VERSION);
    app.setOrganizationName("amwall");
    app.setOrganizationDomain("amwall.local");
    app.setDesktopFileName("amwall");

    // Phase 6.10 — load the embedded translation matching the user's
    // QLocale. qt_add_translations(...) in CMakeLists puts every .qm
    // we ship under the resource path :/i18n/ with the file stem
    // amwall-gui_<locale>. QTranslator::load tries the full locale
    // first (en_US), then strips region (en), then gives up — so
    // shipping just amwall-gui_en_US.qm is enough for now and adding
    // amwall-gui_de.qm later "just works" for German users without
    // any code change here. Falls through to the source strings (also
    // English) if no matching file is found.
    auto *qtBaseTr = new QTranslator(&app);
    if (qtBaseTr->load(QLocale(),
                       QStringLiteral("qtbase"),
                       QStringLiteral("_"),
                       QLibraryInfo::path(QLibraryInfo::TranslationsPath))) {
        app.installTranslator(qtBaseTr);  // standard Qt strings (Cancel, OK)
    }
    auto *appTr = new QTranslator(&app);
    if (appTr->load(QLocale(),
                    QStringLiteral("amwall-gui"),
                    QStringLiteral("_"),
                    QStringLiteral(":/i18n"))) {
        app.installTranslator(appTr);
    }

    // Tray icon keeps the process alive after the last window closes.
    app.setQuitOnLastWindowClosed(false);

    MainWindow w;
    // Settings → general/startMinimized: skip the initial show() so the
    // tray icon is the only visible artifact. The user can still get
    // the window via tray click or "View → Show window".
    QSettings s;
    const bool startMin = s.value("general/startMinimized", false).toBool();
    qInfo().noquote()
        << "main.cpp startup-show check: QSettings file=" << s.fileName()
        << "general/startMinimized=" << startMin
        << "→" << (startMin ? "STAY HIDDEN (tray only)" : "show()");
    if (!startMin) {
        w.show();
    }

    return app.exec();
}
