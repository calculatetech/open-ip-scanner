#pragma once

#include <QColor>
#include <QPalette>
#include <QStyledItemDelegate>

struct ServiceTagDelegateTestAccess;

class ServiceTagDelegate final : public QStyledItemDelegate {
    Q_OBJECT

public:
    explicit ServiceTagDelegate(QObject *parent = nullptr);

    void paint(QPainter *painter,
               const QStyleOptionViewItem &option,
               const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override;
    bool editorEvent(QEvent *event,
                     QAbstractItemModel *model,
                     const QStyleOptionViewItem &option,
                     const QModelIndex &index) override;

signals:
    void serviceActivated(const QModelIndex &index, int serviceIndex);

private:
    struct TagColors {
        QColor foreground;
        QColor background;
        QColor border;
    };

    static TagColors tagColors(const QPalette &palette,
                               QPalette::ColorGroup group,
                               bool selected,
                               bool alternate,
                               const QString &serviceKind);
    QList<QRect> tagRects(const QStyleOptionViewItem &option,
                          const QStringList &tags) const;

    friend struct ServiceTagDelegateTestAccess;
};
