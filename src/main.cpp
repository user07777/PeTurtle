// Qt Essentials
#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QFile>
#include <QDebug>

// Qt UI Loader
#include <QUiLoader>

// Qt Widgets
#include <QStackedWidget>
#include <QListWidget>
#include <QTableWidget>
#include <QHeaderView>

// Qt Threading
#include <QThread>

// STL
#include <filesystem>
#include <format>

#include "dropClass.h"
#include "elf.h"

int main(int argc, char **argv) {
    QApplication app(argc, argv);

    QUiLoader loader;

    QFile file(":/ui/elfTurtle.ui");
    if (!file.open(QFile::ReadOnly)) {
        qWarning() << "Não consegui abrir UI:" << file.errorString();
        return -1;
    }

    QWidget *turtle = loader.load(&file);
    file.close();

    if (!turtle) {
        qWarning() << "Falha ao carregar UI.";
        return -1;
    }
    //drop
    DropArea *dropArea = new DropArea(turtle);
    dropArea->setGeometry(turtle->rect());
    dropArea->hide();

    //sidebar

    auto list = turtle->findChild<QListWidget*>("options");
    auto stack = turtle->findChild<QStackedWidget*>("stackedWidget");

    QMap<QString, QString> pageMap = {
        {"Virus Total", "VirusTotal"},
        {"Yara", "Yara"},
        {"Basic Info", "basic"},
        {"⛓️ IAT", "Iat"},
        {"↗️ EAT", "Eat"},
        {"🧠 Program Headers", "Program"},
        {"📦 Sections Headers", "Sections"},
        {"🔤 Strings", "Strings"},
        {"🗂️ LoadFile", "LoadFile"}
    };

    QObject::connect(list, &QListWidget::currentTextChanged, [stack, pageMap](const QString &text) {
        QString target = pageMap.value(text.trimmed(), "");

        if (target.isEmpty()) {
            return;
        }

        for (int i = 0; i < stack->count(); ++i) {
            if (stack->widget(i)->objectName() == target) {
                stack->setCurrentIndex(i);
                return;
            }
        }
     });
    //handler
    QObject::connect(stack, &QStackedWidget::currentChanged, [&](int index) {
        QString name = stack->widget(index)->objectName();
        const auto elfSTD = dropArea->ELfStd;
        if (name == "LoadFile") {
            dropArea->show();
            dropArea->raise();
        } else {
            dropArea->hide();
        }
        if (name == "Strings") {
            if (!dropArea->inited) {
                return;
            }
            const auto list = turtle->findChild<QListWidget*>("strings");
            if (list) {
                list->clear();

                QThread* thread = QThread::create([=]() {
                    QStringList results;
                    for (const auto& str : dropArea->ELfStd.dumpStrings()) {
                        results << QString::fromStdString(str);
                    }

                    QMetaObject::invokeMethod(list, [list, results]() {
                        for (const auto& item : results) {
                            list->addItem(item);
                        }
                    }, Qt::QueuedConnection);
                });

                QObject::connect(thread, &QThread::finished, thread, &QObject::deleteLater);

                thread->start();
            }
        }


        if (name == "Sections") {
                   if (!dropArea->inited) {
                       return;
                   }
                   const auto table = turtle->findChild<QTableWidget*>("sects");
                   if (table) {

                       auto sections = elfSTD.getSections();
                       table->setRowCount(static_cast<int>(sections.size()));
                       table->setColumnCount(5);

                       QStringList headers = { "Name", "Offset", "Type", "Size", "Entropy" };
                       table->setHorizontalHeaderLabels(headers);

                       int row = 0;
                       for (const auto& sec : sections) {
                           table->setItem(row, 0, new QTableWidgetItem(sec.name.data()));
                           table->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(sec.offset, 0, 16)));
                           table->setItem(row, 2, new QTableWidgetItem(sec.type.data()));
                           table->setItem(row, 3, new QTableWidgetItem(QString::number(sec.size)));

                           table->setItem(row, 4, new QTableWidgetItem(QString::number(sec.entropy)));

                           row++;
                       }


                       table->resizeRowsToContents();
                   }
               }

        if (name == "Program") {
            if (!dropArea->inited) {
                return;
            }
            const auto table = turtle->findChild<QTableWidget*>("tableWidget_4");
            if (table) {

                auto program = elfSTD.getProgram();
                table->setRowCount(static_cast<int>(program.size()));
                table->setColumnCount(6);

                QStringList headers = { "Type", "Offset", "Virtual Address", "Size", "Flags","Align" };
                table->setHorizontalHeaderLabels(headers);

                int row = 0;
                for (const auto& prog : program) {
                    table->setItem(row, 0, new QTableWidgetItem(prog.type.data()));
                    table->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(prog.offset, 0, 16)));
                    table->setItem(row, 2, new QTableWidgetItem(QString("0x%1").arg(prog.vaddr, 0, 16)));

                    table->setItem(row, 2, new QTableWidgetItem(QString::number(prog.filesz)));
                    table->setItem(row, 3, new QTableWidgetItem(QString(prog.flags.data())));

                    table->setItem(row, 4, new QTableWidgetItem(QString::number(prog.align)));

                    row++;
                }


                table->resizeRowsToContents();
            }
    }

        if (name == "Eat") {
            if (!dropArea->inited) {
                return;
            }

            const auto table = turtle->findChild<QTableWidget*>("tableWidget_3");
            if (table) {
                auto eat = elfSTD.getEAT();

                table->setRowCount(static_cast<int>(eat.size()));
                table->setColumnCount(2);

                QStringList headers = { "Name", "Address" };
                table->setHorizontalHeaderLabels(headers);

                int row = 0;
                for (const auto& [name, addr] : eat) {
                    table->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(name)));
                    table->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(addr, 0, 16).toUpper()));
                    row++;
                }
                table->resizeRowsToContents();
            }
        }

        if (name == "Iat") {
            if (!dropArea->inited) {
                return;
            }

            const auto table = turtle->findChild<QTableWidget*>("tableWidget_2");
            if (table) {
                auto iat = elfSTD.getIAT();

                table->setRowCount(static_cast<int>(iat.size()));
                table->setColumnCount(2);

                QStringList headers = { "Name", "Address" };
                table->setHorizontalHeaderLabels(headers);

                int row = 0;
                for (const auto& [name, addr] : iat) {
                    table->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(name)));
                    table->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(addr, 0, 16).toUpper()));
                    row++;
                }
                table->resizeRowsToContents();
            }
        }

        if (name == "basic") {
            if (!dropArea->inited) {
                return;
            }
            const auto list = turtle->findChild<QListWidget*>("listWidget");
            if (list) {
                list->clear();
                auto info = elfSTD.getInfo();
                QFont font = list->font();
                font.setPointSize(15);
                list->setStyleSheet("QListWidget { font-size: 14pt; }");

                list->addItem(std::format("Architecture:{}",elfSTD.getArch()).data());
                list->addItem(std::format("Type:{}",elfSTD.getType()).data());
                list->addItem(std::format("entryPoint:{}",info.entryPoint).data());
                list->addItem(std::format("Compiler:{}",elfSTD.getCompiler()).data());
                list->addItem(std::format("Entropy:{}",elfSTD.getFileEntropy()).data());
            }
        }
    });

    QMainWindow window;
    window.setCentralWidget(turtle);
    window.setWindowTitle("🐢 ElfTurtle 🐢");
    window.setFixedSize(1024,720);
    window.show();
    return app.exec();
}
