//
// Created by kaisy on 17-06-2025.
//

#ifndef DROPCLASS_H
#define DROPCLASS_H
#pragma once
#include <QWidget>
#include <QDragEnterEvent>
#include <QMimeData>
#include <QLabel>
#include "elf.h"
class DropArea : public QWidget {
public:
    explicit DropArea(QWidget *parent = nullptr) : QWidget(parent), ELfStd() {
        setAcceptDrops(true);
    }
    bool inited = false;
    ElfStudio ELfStd;
protected:
    void dragEnterEvent(QDragEnterEvent *event) override {
        if (event->mimeData()->hasUrls()) {
            event->acceptProposedAction();
        }
    }

    void dropEvent(QDropEvent *event) override {
        const auto urls = event->mimeData()->urls();
        if (urls.isEmpty())
            return;

        const QString filePath = urls.first().toLocalFile();
        ELfStd = ElfStudio(std::filesystem::path(filePath.toStdString().c_str()));
        this->hide();
        this->inited = true;
    }
};

#endif //DROPCLASS_H
