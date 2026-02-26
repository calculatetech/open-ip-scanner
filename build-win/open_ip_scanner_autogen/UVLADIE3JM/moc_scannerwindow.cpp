/****************************************************************************
** Meta object code from reading C++ file 'scannerwindow.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.18)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../src/scannerwindow.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'scannerwindow.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.18. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ScannerWindow_t {
    QByteArrayData data[24];
    char stringdata0[296];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ScannerWindow_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ScannerWindow_t qt_meta_stringdata_ScannerWindow = {
    {
QT_MOC_LITERAL(0, 0, 13), // "ScannerWindow"
QT_MOC_LITERAL(1, 14, 9), // "startScan"
QT_MOC_LITERAL(2, 24, 0), // ""
QT_MOC_LITERAL(3, 25, 10), // "finishScan"
QT_MOC_LITERAL(4, 36, 14), // "updateProgress"
QT_MOC_LITERAL(5, 51, 7), // "current"
QT_MOC_LITERAL(6, 59, 5), // "total"
QT_MOC_LITERAL(7, 65, 20), // "addOrUpdateResultRow"
QT_MOC_LITERAL(8, 86, 10), // "ScanResult"
QT_MOC_LITERAL(9, 97, 6), // "result"
QT_MOC_LITERAL(10, 104, 20), // "showTableContextMenu"
QT_MOC_LITERAL(11, 125, 3), // "pos"
QT_MOC_LITERAL(12, 129, 16), // "copySelectedCell"
QT_MOC_LITERAL(13, 146, 15), // "refreshAdapters"
QT_MOC_LITERAL(14, 162, 19), // "applyDefaultTargets"
QT_MOC_LITERAL(15, 182, 9), // "exportCsv"
QT_MOC_LITERAL(16, 192, 10), // "printTable"
QT_MOC_LITERAL(17, 203, 18), // "showSettingsDialog"
QT_MOC_LITERAL(18, 222, 15), // "showAboutDialog"
QT_MOC_LITERAL(19, 238, 17), // "updateWorkerLabel"
QT_MOC_LITERAL(20, 256, 5), // "value"
QT_MOC_LITERAL(21, 262, 22), // "handleTableDoubleClick"
QT_MOC_LITERAL(22, 285, 3), // "row"
QT_MOC_LITERAL(23, 289, 6) // "column"

    },
    "ScannerWindow\0startScan\0\0finishScan\0"
    "updateProgress\0current\0total\0"
    "addOrUpdateResultRow\0ScanResult\0result\0"
    "showTableContextMenu\0pos\0copySelectedCell\0"
    "refreshAdapters\0applyDefaultTargets\0"
    "exportCsv\0printTable\0showSettingsDialog\0"
    "showAboutDialog\0updateWorkerLabel\0"
    "value\0handleTableDoubleClick\0row\0"
    "column"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ScannerWindow[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      14,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   84,    2, 0x08 /* Private */,
       3,    0,   85,    2, 0x08 /* Private */,
       4,    2,   86,    2, 0x08 /* Private */,
       7,    1,   91,    2, 0x08 /* Private */,
      10,    1,   94,    2, 0x08 /* Private */,
      12,    0,   97,    2, 0x08 /* Private */,
      13,    0,   98,    2, 0x08 /* Private */,
      14,    0,   99,    2, 0x08 /* Private */,
      15,    0,  100,    2, 0x08 /* Private */,
      16,    0,  101,    2, 0x08 /* Private */,
      17,    0,  102,    2, 0x08 /* Private */,
      18,    0,  103,    2, 0x08 /* Private */,
      19,    1,  104,    2, 0x08 /* Private */,
      21,    2,  107,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, QMetaType::Int,    5,    6,
    QMetaType::Void, 0x80000000 | 8,    9,
    QMetaType::Void, QMetaType::QPoint,   11,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   20,
    QMetaType::Void, QMetaType::Int, QMetaType::Int,   22,   23,

       0        // eod
};

void ScannerWindow::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ScannerWindow *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->startScan(); break;
        case 1: _t->finishScan(); break;
        case 2: _t->updateProgress((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 3: _t->addOrUpdateResultRow((*reinterpret_cast< const ScanResult(*)>(_a[1]))); break;
        case 4: _t->showTableContextMenu((*reinterpret_cast< const QPoint(*)>(_a[1]))); break;
        case 5: _t->copySelectedCell(); break;
        case 6: _t->refreshAdapters(); break;
        case 7: _t->applyDefaultTargets(); break;
        case 8: _t->exportCsv(); break;
        case 9: _t->printTable(); break;
        case 10: _t->showSettingsDialog(); break;
        case 11: _t->showAboutDialog(); break;
        case 12: _t->updateWorkerLabel((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 13: _t->handleTableDoubleClick((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ScannerWindow::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_meta_stringdata_ScannerWindow.data,
    qt_meta_data_ScannerWindow,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ScannerWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ScannerWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ScannerWindow.stringdata0))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int ScannerWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 14)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 14;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 14)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 14;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
