# UI layout specification

This document is the canonical visual-layout specification for Open IP Scanner. It defines stable geometry and spacing rules for user-interface work; implementation details and screenshots must agree with it. Product ideas remain in [the roadmap](roadmap.md), while this file owns the reusable visual rules used to implement them.

## General layout rules

- Controls that perform comparable jobs use the same width, alignment, tick treatment, and value-column width.
- Dynamic text never changes the size or position of nearby controls. Reserve a fixed display region large enough for every value, and wrap or elide within that region.
- Use a 12-pixel outer margin and 12-pixel separation between major sections. Use 8 pixels between controls within one section.
- Keep labels, controls, and current values in aligned columns. Changing a value must not move any column or resize its window.
- Dense content scrolls vertically inside its page. It must not force controls outside the visible viewport or require horizontal scrolling.
- New layouts must remain usable with the system font and theme. Hard-coded geometry is limited to explicit stability constraints; content pages otherwise expand within their reserved area.

## Settings dialog contract

The Settings dialog is resizable with a minimum client size of 600 by 440 logical pixels so it remains usable on a 640-by-480 display. It prefers 720 by 520 when the active screen has room. Its category navigation is 128 pixels wide. Every page is hosted in a frameless, widget-resizable scroll area so long service, program, OUI, or toolbar content remains vertically reachable. Pages and controls must fit horizontally without a scrollbar at the 600-by-440 minimum.

Appearance dropdowns expand to the available field width and remain visible at
the minimum dialog size. Their text may clip inside the control, but the
control itself never collapses or forces horizontal scrolling.

Performance controls use one shared three-column grid:

- Row labels are right-aligned in a stable 96-pixel column so their trailing
  colons remain visible and line up with labels on other form pages.
- Both horizontal sliders are exactly 180 pixels long, show ticks below the track, and begin at the same horizontal position.
- Both current-value labels occupy a stable 90-pixel column.
- Accuracy details occupy a fixed 44-pixel-high region below the accuracy row. Changing the slider may replace and wrap the text inside that region, but it must not resize either slider, move another row, or change the dialog size.

The concrete constants live in `src/settingslayout.h`. `settings_layout_contract` verifies minimum, preferred, and small-screen geometry and proves the performance row fits inside the minimum page width. `settings_dialog_stability` opens the production dialog offscreen, shrinks it to 600 by 440, verifies every page remains free of horizontal scrolling, moves the Accuracy slider through its range, and verifies that the sliders, description region, and button row retain their geometry.

## Results and details contract

The results table is a concise inventory, not an evidence narrative. Cells display selected values only. The Hostname column omits the DNS suffix for preferred Local, PTR, System, and preliminary names; a preferred mDNS name retains `.local`. Full qualified names remain available in Details. Table cells never word-wrap. Text that exceeds the actual cell width uses right-side character elision at that boundary, rather than stopping at a whitespace, hyphen, or other word boundary. The Hostname column contains no source suffix, badge, confidence label, failure state, or documentary tooltip. Service tags remain the compact `Name:port` and `Unknown:port` forms. Provenance must not add table columns or change row height.

Verified service tags use stable family colors whose luminance adapts to the
active palette; unknown open ports remain neutral. Tag text must maintain at
least 4.5:1 contrast against its fill, and tag fill must maintain at least 3:1
contrast against the cell surface in representative light, dark,
high-contrast, selected, and disabled states. Color is supplemental: the
concise label remains the service-verification identifier, and palette changes
must not alter tag geometry or row height.

The details pane is the on-demand surface for successful per-device evidence. Hostname provenance appears under one `Hostname(s):` heading as a stable list, with the preferred name first. Source labels are short parenthesized descriptors appended immediately after the hostname: `device.example (Local, PTR, System)`. Do not place hostname sources in a detached evidence column because the resulting gap varies awkwardly with hostname length. Every genuine distinct detected name is retained; names that differ only by case or a trailing root dot share one row. If explicit PTR supplies aliases, display only the record matching the scanning adapter's assigned DNS suffix, or qualify its short record with that suffix when no matching FQDN was returned. Keep `.local` mDNS evidence as its own valid name unless `.local` is also the adapter DNS suffix. Matching short Local and System evidence groups with the selected PTR FQDN. Service evidence uses the same restrained inline style, normally `SSH:22 (Verified)` or `Unknown:22 (Open)`. Never detach the status into a third alignment column.

The Details pane remains hidden by default unless its visibility preference is enabled. Its last visible height persists independently of visibility, is clamped when the main window is smaller, and leaves the table usable. Without a saved height, the pane is tall enough to display one IP, hostname, MAC, vendor, and service row without vertical scrolling; additional hostname or service evidence may scroll within the pane.

Changing selection or opening the details pane sends no network traffic. Resolver availability, timeout, malformed-response, and other operational failures belong in diagnostics, not in result cells or per-device prose. Dynamic evidence updates may replace the preferred table value and refresh details, but must preserve the existing ordering, selection, and viewport stability contracts.

## Accessibility and scaling contract

Interactive controls keep stable accessible names and descriptions independent
of whether the toolbar shows icons, text, or both. Labels use focus buddies;
icon-only actions retain keyboard shortcuts and descriptive tooltips. The main
paths are F5 for Scan/Stop, Ctrl+F for result filtering, Ctrl+L for Targets,
Ctrl+R for adapter refresh, Ctrl+Shift+A for automatic targets, and
Ctrl+Shift+T for Terminal.

High-DPI rounding policy is set through Qt's static API before constructing the
application. Startup at 100% and 200% scaling must exit without policy-order
warnings in the automated smoke. All sizes in this specification are logical
pixels, so scaling must not change the Settings dialog's logical 600-by-440
contract.

## Human verification

Open Settings and switch through every category. On Performance, drag both sliders from minimum to maximum and confirm their tracks remain equal in length and position. The accuracy name and description may change, but neither slider, either row, the help paragraph, nor the dialog buttons may move. Confirm the dialog can shrink to 600 by 440, prefers a roomier size on a larger screen, and that pages with more content scroll vertically without ever showing a horizontal scrollbar.

Run a fixture containing conflicting Local, PTR, System, and mDNS names. Confirm the table shows only the preferred first label for non-mDNS evidence, retains `.local` when mDNS is preferred, and elides long values at the cell boundary without wrapping at a word separator. Open Details and confirm `Hostname(s):` lists every genuine distinct detected FQDN with its short source labels immediately appended, collapses matching short and FQDN forms without repeating a source, and does not change the table layout or send new traffic.

Hover each service pill and confirm the pointing-hand cursor appears only over the pill, then click it and confirm the configured service action opens. Confirm About retains its compact message-box appearance with the full-size program icon on the left and that its links, along with Usage Guide links, open through the desktop URL handler. During a scan, confirm the status bar contains only state, progress, and `Mode: <Accuracy>`; after completion or stopping, confirm it contains only the completion state and detected-host count. Resize Details, restart the application, and confirm its height is restored.

At 200% scale, repeat the primary workflow using only the keyboard. Confirm
focus is visible, every control is announced with a useful name and role by the
desktop accessibility inspector or screen reader, every Settings page remains
reachable, and light, dark, and high-contrast themes retain legible selection
and service colors.
