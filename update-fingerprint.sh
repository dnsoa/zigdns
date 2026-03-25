#!/bin/bash
# 更新 build.zig.zon 中的 fingerprint

set -e

echo "Updating build.zig.zon fingerprint..."

# 获取 Zig 构建时输出的正确 fingerprint
OUTPUT=$(zig build 2>&1)

if echo "$OUTPUT" | grep -q "fingerprint mismatch"; then
    # 提取实际的 fingerprint
    ACTUAL=$(echo "$OUTPUT" | grep "actual:" | sed 's/.*actual:.*0x\([0-9a-fA-F]*\).*/\1/' | tr '[:lower:]' '[:upper:]')

    if [ -n "$ACTUAL" ]; then
        echo "Found fingerprint: 0x$ACTUAL"

        # 更新 build.zig.zon
        sed -i "s/\.fingerprint = 0x[0-9a-fA-F]*/.fingerprint = 0x$ACTUAL/" build.zig.zon

        echo "✓ Updated build.zig.zon"
        echo ""
        echo "Please verify the changes:"
        grep "fingerprint" build.zig.zon
    else
        echo "✗ Could not extract fingerprint from build output"
        echo "Output:"
        echo "$OUTPUT"
        exit 1
    fi
else
    echo "✓ Fingerprint is already correct"
fi
