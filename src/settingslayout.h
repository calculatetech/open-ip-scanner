#pragma once

namespace settingslayout {

constexpr int kMinimumDialogWidth = 600;
constexpr int kMinimumDialogHeight = 440;
constexpr int kPreferredDialogWidth = 720;
constexpr int kPreferredDialogHeight = 520;
constexpr int kScreenMargin = 40;
constexpr int kOuterMargin = 12;
constexpr int kSectionSpacing = 12;
constexpr int kControlSpacing = 8;
constexpr int kNavigationWidth = 128;
constexpr int kRowLabelWidth = 82;
constexpr int kSliderWidth = 180;
constexpr int kValueWidth = 90;
constexpr int kDynamicDescriptionHeight = 44;

constexpr int kAvailablePageWidth =
    kMinimumDialogWidth - (2 * kOuterMargin) - kNavigationWidth - kSectionSpacing;
constexpr int kPerformanceRowWidth =
    kRowLabelWidth + (2 * kSectionSpacing) + kSliderWidth + kValueWidth;

constexpr int initialDialogDimension(int available,
                                     int minimum,
                                     int preferred)
{
    const int safeAvailable = available - kScreenMargin;
    if (safeAvailable <= minimum) {
        return minimum;
    }
    return safeAvailable < preferred ? safeAvailable : preferred;
}

static_assert(kPreferredDialogWidth >= kMinimumDialogWidth &&
                  kPreferredDialogHeight >= kMinimumDialogHeight,
              "Preferred Settings geometry must not be smaller than its minimum");
static_assert(kPerformanceRowWidth <= kAvailablePageWidth - (2 * kOuterMargin),
              "Performance rows must fit without resizing the dialog");

} // namespace settingslayout
