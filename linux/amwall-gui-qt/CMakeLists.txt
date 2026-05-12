cmake_minimum_required(VERSION 3.16)
project(amwall-gui LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Qt's signal/slot meta-object machinery + .ui form support + .qrc
# resource embedding — generated at build time.
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Qt6 from qt6-base-dev on Mint 22 / Ubuntu 24.04. Components needed
# so far: Widgets (QMainWindow, menus, tray, dashboard) + DBus
# (talking to amwall-daemon over the system bus) + Network
# (QHostAddress for IPv4 validation in the rule editor). Phases 6.5+
# may add Concurrent (background worker for /proc walks) and
# LinguistTools (translations).
find_package(Qt6 REQUIRED COMPONENTS Widgets DBus Network)

# AMWALL_VERSION is baked into the binary so --version and the About
# box show the same string the .deb is built with. Bumped per phase.
add_compile_definitions(AMWALL_VERSION="0.1.0+phase6.9")

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
