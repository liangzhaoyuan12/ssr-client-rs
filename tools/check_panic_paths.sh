#!/usr/bin/env bash
# Q4: 生产路径 panic 清零门禁
# 扫描 src/ 下 unwrap()/expect()/panic!/unreachable!，
# 排除 #[cfg(test)] 块（测试 mod 通常在文件尾）与 src/bin/（bin 允许 fail-fast）。
# 命中白名单的行不算违规；白名单只减不增。
set -u
cd "$(dirname "$0")/.."

# ---- 白名单（每条附一行理由；格式: "file:line-substr"）----
# 目前为空——所有生产路径 panic 都必须改造，而不是加白。
WHITELIST=()

# 收集扫描行: 从每个非 bin 的 .rs 文件里，
# 跳过首个 "#[cfg(test)]" 之后的全部内容（该行起为测试块）。
scan() {
  local f
  while IFS= read -r f; do
    awk '/#\[cfg\(test\)\]/{exit} /unwrap\(\)|expect\(|panic!|unreachable!/{printf "%s:%d:%s\n", FILENAME, FNR, $0}' "$f"
  done < <(find src -name '*.rs' -not -path 'src/bin/*' | sort)
}

hits=$(scan)

# 过滤白名单
violations=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  skip=0
  for w in "${WHITELIST[@]:-}"; do
    [ -n "$w" ] && [ "${line#*:*:}" != "${line#*:*:}" ] && case "$line" in *"$w"*) skip=1;; esac
  done
  [ "$skip" -eq 0 ] && violations+="$line"$'\n'
done <<< "$hits"

count=$(printf '%s' "$violations" | grep -c . || true)

if [ "$count" -gt 0 ]; then
  echo "FAIL: $count production-path panic site(s):"
  printf '%s' "$violations"
  exit 1
fi
echo "OK: 0 production-path panic sites"
exit 0
