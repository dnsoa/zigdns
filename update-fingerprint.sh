#!/bin/bash
# 更新 build.zig.zon 中的 fingerprint

set -e

echo "Updating build.zig.zon fingerprint..."

# 获取 Zig 构建时输出的正确 fingerprint（允许非零退出码以便捕获 mismatch 输出）
OUTPUT=$(zig build 2>&1 || true)

if echo "$OUTPUT" | grep -q "fingerprint"; then
    # 提取建议或实际的 fingerprint（保持小写十六进制，兼容 Zig 规范）
    ACTUAL=$(echo "$OUTPUT" | grep -Eo '0x[0-9a-fA-F]+' | tail -n 1)

    if [ -n "$ACTUAL" ]; then
        echo "Found fingerprint: $ACTUAL"

        # 使用临时文件替换，兼容 macOS BSD sed 与 GNU sed
        sed "s/\.fingerprint = 0x[0-9a-fA-F]*/.fingerprint = $ACTUAL/" build.zig.zon > build.zig.zon.tmp
        mv build.zig.zon.tmp build.zig.zon

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
