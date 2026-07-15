#pragma once

#include <QColor>
#include <QPalette>
#include <QStyledItemDelegate>

struct ServiceTagDelegateTestAccess;
class QAbstractItemView;
class QWidget;

class ServiceTagDelegate final : public QStyledItemDelegate {
    Q_OBJECT

public:
    explicit ServiceTagDelegate(QAbstractItemView *view = nullptr);

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

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

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
    int tagIndexAt(const QStyleOptionViewItem &option,
                   const QModelIndex &index,
                   const QPoint &position) const;

    QAbstractItemView *view_ = nullptr;
    QWidget *viewport_ = nullptr;

    friend struct ServiceTagDelegateTestAccess;
};
