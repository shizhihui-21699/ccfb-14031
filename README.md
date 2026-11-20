# 离线授权校验符号分析工具 (License-Check Symbolic Analyzer)

在发布前对**自己的**离线授权校验做防御性审计:给定编译好的 arm64 Mach-O
程序,自动推导出哪些输入能让校验函数走到"授权通过"的返回路径,并给出具体的
输入字节。工具只在 Z3 **证明**某条成功路径可行时才输出输入;推不动时明确
报告卡在哪里,绝不猜测。

> 仅用于对自有软件的授权安全测试。请勿用于绕过他人产品的保护机制。

## 它解决什么问题

授权校验里常见的障碍——循环、查表、哈希片段、多层条件——使得暴力穷举不现实。
本工具用**符号执行 + SMT 求解**系统地处理它们:

| 难点 | 处理方式 |
|------|----------|
| 多层条件分支 | 每条依赖输入的分支派生两个状态,带互补路径约束,DFS 探索并用求解器剪枝 |
| 循环 | 有界展开(`--max-unroll`),回边计数,超限即报告卡点而非死循环 |
| 查表(如 S-box) | 符号索引读表达为嵌套 ITE 的纯位向量公式,对求解器友好 |
| 哈希片段(如 FNV-1a) | 异或/乘法/掩码逐操作翻译成 Z3 位向量约束,直接求解逆像 |
| 长度依赖(`strlen`) | 按候选长度逐档分析,输入建模为定长符号字节 + 显式 NUL 终止符 |
| 库函数 | 内置 `strlen/strcmp/memcmp/memcpy/memset` 的符号模型 |

## 目录结构

```
analyzer/
  macho.py     纯 Python 的 arm64 Mach-O 解析(段/节/符号/stub 绑定/字符串)
  expr.py      Z3 位向量封装 + 内存模型(全局/栈/输入,符号索引查表)
  engine.py    AArch64 符号执行引擎(指令语义、标志位、分叉、探索、卡点)
  cli.py       命令行驱动与报告
analyze.py     入口脚本
tests/
  src/         六个难度递增的校验程序 + 边界用例(C 源码)
  build.sh     编译全部测试目标
  test_analyzer.py  端到端与单元测试
```

## 准备环境

需要 Python 3、clang(arm64)、capstone、z3-solver。

```bash
python3 -m venv --system-site-packages .venv   # 复用系统已装的 z3
.venv/bin/pip install capstone
./tests/build.sh                               # 编译测试目标
```

## 使用

```bash
# 基本用法:在长度 1..16 内自动扫描能通过 _check 的输入
.venv/bin/python -I analyze.py path/to/program --verify

# 指定长度范围与目标符号
.venv/bin/python -I analyze.py tests/bin/lvl6_layered \
    --target _check --min-len 11 --max-len 11 --verify

# 调整分析深度与超时
.venv/bin/python -I analyze.py program --timeout 90 --max-unroll 128 \
    --max-states 50000 --solver-timeout 30000
```

输出示例:

```
=== input length 11 ===
  states=75 forks=37 insns=489 sat=1 unsat=27 time=1.16s
  [+] PASSING INPUT FOUND (11 bytes)
      raw bytes : 554c542d0ada100e2d3531
      escaped   : ULT-\x0a\xda\x10\x0e-51
      verify    : MATCH (real binary returns success) [exit 0, 'LICENSE_OK_GRANTED']
```

## 六个测试档位(难度递增)

| 档 | 程序 | 考察点 | 实测耗时 |
|----|------|--------|---------|
| 1 | lvl1_compare | 逐字节直接比较 + 循环 | ~0.2s |
| 2 | lvl2_conditions | 无循环多层算术/位/区间条件 | ~0.1s |
| 3 | lvl3_loop_sum | 循环累加校验和 + 边界约束 | ~0.2s |
| 4 | lvl4_table | 循环内 256 项查表 | ~0.7s |
| 5 | lvl5_hash | 循环内 FNV-1a 哈希片段 | ~1.0s |
| 6 | lvl6_layered | 上述全部 + 五层独立拒绝分支 + 内部函数调用 | ~1.2s |

每档都能恢复出一个真实可通过的输入(查表/校验和/哈希类约束存在多个逆像时,
工具给出其中任意一个,并用真实程序回验)。

## 诚实的卡点报告

工具不会在推不动时编造结果。当前会明确区分:

- `no feasible success path` —— 该长度下所有路径都拒绝(约束无解,非引擎故障)
- `unsupported` —— 遇到未建模的指令(如浮点 `scvtf/fcmp`、向量指令),附地址
- `symbolic-memory` —— 符号地址访问了未建模的内存区域
- `loop-unroll-cap` —— 循环回边超过 `--max-unroll`,附回边地址
- `state-budget` / `instruction-budget` —— 触及状态数/指令数上限
- `solver-timeout` / 墙钟超时 —— 求解器或整体预算耗尽,分析不完整

## 能力边界(已知限制)

- 仅支持 **arm64 Mach-O**、定位到具名校验函数(默认 `_check`)。
- 整数/位向量语义;**不支持浮点与 SIMD/向量**指令(遇到即报告卡点)。
- 输入按定长 C 字符串建模,默认约束无内嵌 NUL;不建模数据相关的变长输入。
- 符号地址仅支持对**已知常量区域(表/字符串)和输入缓冲**的字节读;其它
  符号内存访问报 `symbolic-memory`。
- 内部函数调用有界(默认深度 8)内联展开;间接调用仅在目标可确定时支持。
- 路径/时间/展开均有上限,刻意保证终止性;调大上限可换更深分析,成本随之上升。

## 运行测试

```bash
.venv/bin/python -I tests/test_analyzer.py
```
