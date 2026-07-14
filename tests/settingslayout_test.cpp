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
    require(settingslayout::kDialogWidth == 600);
    require(settingslayout::kDialogHeight == 440);
    require(settingslayout::kDialogWidth <= 600);
    require(settingslayout::kDialogHeight <= 440);
    require(settingslayout::kSliderWidth == 180);
    require(settingslayout::kValueWidth == 90);
    require(settingslayout::kDynamicDescriptionHeight == 44);
    require(settingslayout::kPerformanceRowWidth <=
            settingslayout::kAvailablePageWidth - (2 * settingslayout::kOuterMargin));
    return EXIT_SUCCESS;
}
