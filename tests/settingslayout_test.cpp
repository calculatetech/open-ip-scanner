#include "settingslayout.h"

#include <cstdlib>

namespace {

void require(bool condition)
{
    if (!condition) {
        std::abort();
    }
}

} // namespace

int main()
{
    require(settingslayout::kMinimumDialogWidth == 600);
    require(settingslayout::kMinimumDialogHeight == 440);
    require(settingslayout::kPreferredDialogWidth == 720);
    require(settingslayout::kPreferredDialogHeight == 520);
    require(settingslayout::initialDialogDimension(640, 600, 720) == 600);
    require(settingslayout::initialDialogDimension(480, 440, 520) == 440);
    require(settingslayout::initialDialogDimension(1920, 600, 720) == 720);
    require(settingslayout::initialDialogDimension(1080, 440, 520) == 520);
    require(settingslayout::kSliderWidth == 180);
    require(settingslayout::kValueWidth == 90);
    require(settingslayout::kDynamicDescriptionHeight == 44);
    require(settingslayout::kPerformanceRowWidth <=
            settingslayout::kAvailablePageWidth - (2 * settingslayout::kOuterMargin));
    return EXIT_SUCCESS;
}
