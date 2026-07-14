#pragma once

#include <QStyledItemDelegate>

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
    QList<QRect> tagRects(const QStyleOptionViewItem &option,
                          const QStringList &tags) const;
};
