/****************************************************************************
** Meta object code from reading C++ file 'scannerwindow.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.8.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../src/scannerwindow.h"
#include <QtCore/qmetatype.h>

#include <QtCore/qtmochelpers.h>

#include <memory>


#include <QtCore/qxptype_traits.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'scannerwindow.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.8.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {
struct qt_meta_tag_ZN13ScannerWindowE_t {};
} // unnamed namespace


#ifdef QT_MOC_HAS_STRINGDATA
static constexpr auto qt_meta_stringdata_ZN13ScannerWindowE = QtMocHelpers::stringData(
    "ScannerWindow",
    "startScan",
    "",
    "finishScan",
    "updateProgress",
    "current",
    "total",
    "addOrUpdateResultRow",
    "ScanResult",
    "result",
    "showTableContextMenu",
    "pos",
    "copySelectedCell",
    "refreshAdapters",
    "applyDefaultTargets",
    "exportCsv",
    "printTable",
    "showSettingsDialog",
    "showAboutDialog",
    "updateWorkerLabel",
    "value",
    "handleTableDoubleClick",
    "row",
    "column",
    "showHeaderContextMenu",
    "toggleSearchBar"
);
#else  // !QT_MOC_HAS_STRINGDATA
#error "qtmochelpers.h not found or too old."
#endif // !QT_MOC_HAS_STRINGDATA

Q_CONSTINIT static const uint qt_meta_data_ZN13ScannerWindowE[] = {

 // content:
      12,       // revision
       0,       // classname
       0,    0, // classinfo
      16,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,  110,    2, 0x08,    1 /* Private */,
       3,    0,  111,    2, 0x08,    2 /* Private */,
       4,    2,  112,    2, 0x08,    3 /* Private */,
       7,    1,  117,    2, 0x08,    6 /* Private */,
      10,    1,  120,    2, 0x08,    8 /* Private */,
      12,    0,  123,    2, 0x08,   10 /* Private */,
      13,    0,  124,    2, 0x08,   11 /* Private */,
      14,    0,  125,    2, 0x08,   12 /* Private */,
      15,    0,  126,    2, 0x08,   13 /* Private */,
      16,    0,  127,    2, 0x08,   14 /* Private */,
      17,    0,  128,    2, 0x08,   15 /* Private */,
      18,    0,  129,    2, 0x08,   16 /* Private */,
      19,    1,  130,    2, 0x08,   17 /* Private */,
      21,    2,  133,    2, 0x08,   19 /* Private */,
      24,    1,  138,    2, 0x08,   22 /* Private */,
      25,    0,  141,    2, 0x08,   24 /* Private */,

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
    QMetaType::Void, QMetaType::QPoint,   11,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject ScannerWindow::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_meta_stringdata_ZN13ScannerWindowE.offsetsAndSizes,
    qt_meta_data_ZN13ScannerWindowE,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_tag_ZN13ScannerWindowE_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<ScannerWindow, std::true_type>,
        // method 'startScan'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'finishScan'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'updateProgress'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'addOrUpdateResultRow'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const ScanResult &, std::false_type>,
        // method 'showTableContextMenu'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QPoint &, std::false_type>,
        // method 'copySelectedCell'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'refreshAdapters'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'applyDefaultTargets'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'exportCsv'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'printTable'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'showSettingsDialog'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'showAboutDialog'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'updateWorkerLabel'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'handleTableDoubleClick'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'showHeaderContextMenu'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QPoint &, std::false_type>,
        // method 'toggleSearchBar'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void ScannerWindow::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    auto *_t = static_cast<ScannerWindow *>(_o);
    if (_c == QMetaObject::InvokeMetaMethod) {
        switch (_id) {
        case 0: _t->startScan(); break;
        case 1: _t->finishScan(); break;
        case 2: _t->updateProgress((*reinterpret_cast< std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[2]))); break;
        case 3: _t->addOrUpdateResultRow((*reinterpret_cast< std::add_pointer_t<ScanResult>>(_a[1]))); break;
        case 4: _t->showTableContextMenu((*reinterpret_cast< std::add_pointer_t<QPoint>>(_a[1]))); break;
        case 5: _t->copySelectedCell(); break;
        case 6: _t->refreshAdapters(); break;
        case 7: _t->applyDefaultTargets(); break;
        case 8: _t->exportCsv(); break;
        case 9: _t->printTable(); break;
        case 10: _t->showSettingsDialog(); break;
        case 11: _t->showAboutDialog(); break;
        case 12: _t->updateWorkerLabel((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 13: _t->handleTableDoubleClick((*reinterpret_cast< std::add_pointer_t<int>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<int>>(_a[2]))); break;
        case 14: _t->showHeaderContextMenu((*reinterpret_cast< std::add_pointer_t<QPoint>>(_a[1]))); break;
        case 15: _t->toggleSearchBar(); break;
        default: ;
        }
    }
}

const QMetaObject *ScannerWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ScannerWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ZN13ScannerWindowE.stringdata0))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int ScannerWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 16)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 16;
    }
    if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 16)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 16;
    }
    return _id;
}
QT_WARNING_POP
