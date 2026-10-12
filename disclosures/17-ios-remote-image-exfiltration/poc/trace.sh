#!/usr/bin/env bash
# Finding 17: regenerates the static trace from pristine checkouts (read-only; no network).
#   IOS     = tinfoil-ios clone (checked at cd5824e)
#   TEXTUAL = tinfoilsh/textual clone (checked at 5b20cd9 = v0.0.11, the revision tinfoil-ios pins)
# If you have no textual clone: git clone https://github.com/tinfoilsh/textual && git -C textual checkout 5b20cd9
set -euo pipefail
IOS="${IOS:-/root/tinfoil-review/repos/tinfoil-ios}"
TEXTUAL="${TEXTUAL:-/root/tinfoil-review/work/ios-swift/textual}"
[ "$(git -C "$IOS" rev-parse --short=7 HEAD)" = cd5824e ] || { echo "tinfoil-ios is not at cd5824e"; exit 1; }
[ "$(git -C "$TEXTUAL" rev-parse --short=7 HEAD)" = 5b20cd9 ] || { echo "textual is not at 5b20cd9"; exit 1; }
show() { echo; echo "== $1/$2:$3"; sed -n "$3p" "$1/$2" | sed "s/^/    /"; }
T=Sources/Textual

echo "# tinfoil-ios $(git -C "$IOS" rev-parse --short HEAD), textual $(git -C "$TEXTUAL" rev-parse --short HEAD) ($(git -C "$TEXTUAL" tag --points-at HEAD))"

echo; echo "## 1. App pins textual 0.0.11 @ 5b20cd9"
show "$IOS" TinfoilChat.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved 131,137

echo; echo "## 2. Assistant markdown is rendered with StructuredText(markdown:) and no loader override"
show "$IOS" TinfoilChat/Views/LaTeXMarkdownView.swift 22,36
echo; echo "== assistant render sites (MessageView.swift)"
grep -n "LaTeXMarkdownView(\|StructuredText(markdown" "$IOS/TinfoilChat/Views/MessageView.swift" | sed "s/^/    /"
echo; echo "== loader overrides anywhere in the app (expect none):"
if grep -rn "imageAttachmentLoader\|emojiAttachmentLoader\|AttachmentLoader" "$IOS/TinfoilChat" "$IOS/TinfoilShared" "$IOS/TinfoilShareExtension"; then echo "    FOUND (finding may be fixed)"; else echo "    none"; fi
echo "== ATS exceptions (expect none => https:// to any host allowed):"
if grep -rln "NSAppTransportSecurity\|NSAllowsArbitraryLoads" "$IOS" --include=*.plist --include=*.pbxproj; then :; else echo "    none"; fi

echo; echo "## 3. Textual: StructuredText wraps every parsed string in WithAttachments"
show "$TEXTUAL" $T/StructuredText/StructuredText.swift 116,128
echo; echo "## 4. WithAttachments resolves every imageURL run in .task(id:) as soon as the text renders (also mid-stream)"
show "$TEXTUAL" $T/Internal/Attachment/WithAttachments.swift 33,51
show "$TEXTUAL" $T/Internal/Attachment/WithAttachments.swift 86,95
echo; echo "## 5. Default image loader is the URL loader"
show "$TEXTUAL" $T/Attachment/AttachmentLoader.swift 59,62
show "$TEXTUAL" $T/Attachment/URLAttachmentLoader.swift 19,28
echo; echo "## 6. ImageLoader = URLSession(.default + Accept: image/*).data(from:) - the GET is sent before any content check"
show "$TEXTUAL" $T/Internal/Image/ImageLoader.swift 20,22
show "$TEXTUAL" $T/Internal/Image/ImageLoader.swift 76,86
echo; echo "## 7. Parser: Foundation AttributedString(markdown:) with default (full) options => imageURL runs for ![alt](url)"
show "$TEXTUAL" $T/MarkdownParser/AttributedStringMarkdownParser.swift 44,52
echo "== the app itself relies on Foundation producing imageURL runs for assistant markdown:"
grep -n "imageURL" "$IOS/TinfoilChat/Services/Speech/SpeechTextProcessor.swift" 2>/dev/null | sed "s/^/    SpeechTextProcessor.swift:/" || grep -rn "run.imageURL" "$IOS/TinfoilChat" | sed "s/^/    /"
grep -n "image.com" "$IOS/TinfoilChatTests/SpeechTextTests.swift" | sed "s/^/    SpeechTextTests.swift:/"

echo; echo "## 8. Attacker text reaches the model by default: web search on, tinfoil web-search events requested"
grep -n "webSearchEnabled" "$IOS/TinfoilChat/Models/ChatModels.swift" | head -3 | sed "s/^/    ChatModels.swift:/"
show "$IOS" TinfoilChat/ViewModels/ChatViewModel.swift 1746,1753

echo; echo "## 9. GenUI: render_image -> AsyncImage on any https URL (only if the control plane enables the widget)"
show "$IOS" TinfoilChat/Views/GenUI/GenUIStyle.swift 95,103
