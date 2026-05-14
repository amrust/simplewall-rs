cmake_minimum_required(VERSION 3.16)
project(amwall-gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt's signal/slot meta-object machinery + .ui form support + .qrc
# resource embedding — generated at build time.
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Qt6 from qt6-base-dev on Mint 22 / Ubuntu 24.04. Components:
#   Widgets       — QMainWindow, menus, tray, dashboard
#   DBus          — talking to amwall-daemon over the system bus
#   Network       — QHostAddress for IPv4 validation in the rule editor
#   LinguistTools — Phase 6.10: lupdate / lrelease for tr() strings
#                   (no actual translations shipped yet — only the
#                   en_US source .ts so future contributors can run
#                   `lupdate amwall-gui_*.ts` and start translating)
find_package(Qt6 REQUIRED COMPONENTS Widgets DBus Network LinguistTools)

# AMWALL_VERSION is baked into the binary so --version and the About
# box show the same string the .deb is built with. Bumped per phase.
add_compile_definitions(AMWALL_VERSION="0.1.0+phase6.10")

add_executable(amwall-gui
    src/main.cpp
    src/mainwindow.cpp
    src/mainwindow.h
    src/dbusclient.cpp
    src/dbusclient.h
    src/dashboard.cpp
    src/dashboard.h
    src/connectprompt.cpp
    src/connectprompt.h
    src/promptcoordinator.cpp
    src/promptcoordinator.h
    src/userrulestab.cpp
    src/userrulestab.h
    src/ruleeditor.cpp
    src/ruleeditor.h
    src/connectionstab.cpp
    src/connectionstab.h
    src/packetslogtab.cpp
    src/packetslogtab.h
    src/appstab.cpp
    src/appstab.h
    src/blocklisttab.cpp
    src/blocklisttab.h
    src/settingsdialog.cpp
    src/settingsdialog.h
)

target_link_libraries(amwall-gui PRIVATE
    Qt6::Widgets
    Qt6::DBus
    Qt6::Network
)

# Phase 6.10 — translation infrastructure.
#
# qt_add_translations runs lupdate over every tr() call in our source
# tree and emits/updates the .ts files listed; lrelease compiles each
# .ts to a .qm at build time and embeds them as a Qt resource the
# binary picks up at runtime via QTranslator::load("amwall-gui_xx").
#
# Ship just en_US for now — the source language. Adding a real locale
# is a one-line addition here (`translations/amwall-gui_de.ts`) plus
# someone with German to fill it in. lupdate keeps the .ts files in
# sync with the source automatically on every build.
qt_add_translations(amwall-gui
    TS_FILES
        translations/amwall-gui_en_US.ts
)
