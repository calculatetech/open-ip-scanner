# UI layout specification

This document is the canonical visual-layout specification for Open IP Scanner. It defines stable geometry and spacing rules for user-interface work; implementation details and screenshots must agree with it. Product ideas remain in [the roadmap](roadmap.md), while this file owns the reusable visual rules used to implement them.

## General layout rules

- Controls that perform comparable jobs use the same width, alignment, tick treatment, and value-column width.
- Dynamic text never changes the size or position of nearby controls. Reserve a fixed display region large enough for every value, and wrap or elide within that region.
- Use a 12-pixel outer margin and 12-pixel separation between major sections. Use 8 pixels between controls within one section.
- Keep labels, controls, and current values in aligned columns. Changing a value must not move any column or resize its window.
- Dense content scrolls inside its page. It must not enlarge the containing window or force controls outside the visible viewport.
- New layouts must remain usable with the system font and theme. Hard-coded geometry is limited to explicit stability constraints; content pages otherwise expand within their reserved area.

## Settings dialog contract

The Settings dialog is exactly 600 by 440 logical pixels and must never request or force a larger size. Its category navigation is 128 pixels wide. Every page is hosted in a frameless, widget-resizable scroll area so long service, program, OUI, or toolbar content remains reachable without changing the dialog geometry.

Performance controls use one shared three-column grid:

- Row labels occupy a stable 82-pixel column.
- Both horizontal sliders are exactly 180 pixels long, show ticks below the track, and begin at the same horizontal position.
- Both current-value labels occupy a stable 90-pixel column.
- Accuracy details occupy a fixed 44-pixel-high region below the accuracy row. Changing the slider may replace and wrap the text inside that region, but it must not resize either slider, move another row, or change the dialog size.

The concrete constants live in `src/settingslayout.h`. `settings_layout_contract` verifies the maximum dialog geometry and proves the performance row fits inside the specified page width. `settings_dialog_stability` opens the production dialog offscreen, moves the Accuracy slider through its range, and verifies that the dialog, sliders, description region, and button row retain their geometry.

## Results and details contract

The results table is a concise inventory, not an evidence narrative. Cells display selected values only. The Hostname column omits the DNS suffix for preferred Local, PTR, System, and preliminary names; a preferred mDNS name retains `.local`. Full qualified names remain available in Details. Table cells never word-wrap. Text that exceeds the actual cell width uses right-side character elision at that boundary, rather than stopping at a whitespace, hyphen, or other word boundary. The Hostname column contains no source suffix, badge, confidence label, failure state, or documentary tooltip. Service tags remain the compact `Name:port` and `Unknown:port` forms. Provenance must not add table columns or change row height.

Verified service tags use stable family colors whose luminance adapts to the
active palette; unknown open ports remain neutral. Tag text must maintain at
least 4.5:1 contrast against its fill, and tag fill must maintain at least 3:1
contrast against the cell surface in representative light, dark,
high-contrast, selected, and disabled states. Color is supplemental: the
concise label remains the service-verification identifier, and palette changes
must not alter tag geometry or row height.

The details pane is the on-demand surface for successful per-device evidence. Hostname provenance appears under one `Hostname(s):` heading as a stable list, with the preferred name first. Source labels are short parenthesized descriptors appended immediately after the hostname: `device.example (Local, PTR, System)`. Do not place hostname sources in a detached evidence column because the resulting gap varies awkwardly with hostname length. Every genuine distinct detected name is retained; names that differ only by case or a trailing root dot share one row. If explicit PTR supplies aliases, display only the record matching the scanning adapter's assigned DNS suffix, or qualify its short record with that suffix when no matching FQDN was returned. Keep `.local` mDNS evidence as its own valid name unless `.local` is also the adapter DNS suffix. Matching short Local and System evidence groups with the selected PTR FQDN. Service evidence uses the same restrained style, normally `(Verified)` or `(Open)`.

Changing selection or opening the details pane sends no network traffic. Resolver availability, timeout, malformed-response, and other operational failures belong in diagnostics, not in result cells or per-device prose. Dynamic evidence updates may replace the preferred table value and refresh details, but must preserve the existing ordering, selection, and viewport stability contracts.

## Human verification

Open Settings and switch through every category. On Performance, drag both sliders from minimum to maximum and confirm their tracks remain equal in length and position. The accuracy name and description may change, but neither slider, either row, the help paragraph, nor the dialog buttons may move. Confirm the dialog remains 600 by 440 and that pages with more content scroll internally.

Run a fixture containing conflicting Local, PTR, System, and mDNS names. Confirm the table shows only the preferred first label for non-mDNS evidence, retains `.local` when mDNS is preferred, and elides long values at the cell boundary without wrapping at a word separator. Open Details and confirm `Hostname(s):` lists every genuine distinct detected FQDN with its short source labels immediately appended, collapses matching short and FQDN forms without repeating a source, and does not change the table layout or send new traffic.
