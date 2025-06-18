cmake_minimum_required(VERSION 3.16)
project(elfstudio)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_PREFIX_PATH "/opt/Qt/6.9.1/gcc_64")

# 🧠 Headers 🧠
set(SOURCES
        src/elf.cpp
        src/elf.h
        src/utils.h
)

# 🔥 CLI build🔥
add_executable(elfstudio-cli src/mainCLI.cpp ${SOURCES}
        src/dropClass.h)

# 🔥 QT build 🔥
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets UiTools)

add_executable(elfstudio-qt src/main.cpp ${SOURCES})

target_link_libraries(elfstudio-qt
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::UiTools
)
qt_add_resources(TURTLE_RES src/turtle.qrc)
qt_add_resources(ASSETS_RES assets/assets.qrc)

target_sources(elfstudio-qt PRIVATE ${TURTLE_RES} ${ASSETS_RES})
