#pragma once

namespace settingslayout {

constexpr int kDialogWidth = 600;
constexpr int kDialogHeight = 440;
constexpr int kOuterMargin = 12;
constexpr int kSectionSpacing = 12;
constexpr int kControlSpacing = 8;
constexpr int kNavigationWidth = 128;
constexpr int kRowLabelWidth = 82;
constexpr int kSliderWidth = 180;
constexpr int kValueWidth = 90;
constexpr int kDynamicDescriptionHeight = 44;

constexpr int kAvailablePageWidth =
    kDialogWidth - (2 * kOuterMargin) - kNavigationWidth - kSectionSpacing;
constexpr int kPerformanceRowWidth =
    kRowLabelWidth + (2 * kSectionSpacing) + kSliderWidth + kValueWidth;

static_assert(kDialogWidth <= 600 && kDialogHeight <= 440,
              "Settings must fit within the documented maximum size");
static_assert(kPerformanceRowWidth <= kAvailablePageWidth - (2 * kOuterMargin),
              "Performance rows must fit without resizing the dialog");

} // namespace settingslayout
