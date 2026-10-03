# pe-inspect — 离线 PE32+ 导入表与 RVA 映射检查后端

一个纯本地、只读的 Windows PE32+ 文件检查服务。输入项目内的合成 64 位 PE 文件，
解析节表与普通导入表，列出导入的 DLL、按名称/序号导入的函数及其来源文件偏移。
提供 HTTP API 与 CLI，报告存入 SQLite。

**不做的事**：不执行或加载被检查文件，不调用系统加载器，不打开/追踪真实 DLL，
不修改现有程序，不依赖外部反汇编工具，不做机器码反汇编、病毒分析或数字签名验证，
不枚举用户系统程序，不访问任何在线服务。

## 支持的 PE 子集

- 仅 PE32+（可选头 magic `0x20b`），机器类型仅 AMD64（`0x8664`）。
- 32 位 PE（`0x10b`）与其他机器类型：明确报 `UNSUPPORTED_*` 错误。
- 仅解析**普通导入表**（数据目录索引 1）。延迟导入（目录 13）存在时只在
  报告中标注 `delayImportPresent`，不解析；绑定导入不解析。
- 导入描述符读到全零终止项为止；优先使用 `OriginalFirstThunk`，为 0 时
  回退到 `FirstThunk`（报告中 `usedFallback=true`）。
- 64 位 thunk 最高位（bit 63）区分序号导入，全部用 BigInt 运算，不经过
  有符号 32 位位运算；名称导入读取 hint + 零终止 ASCII 名。

## 地址口径（RVA / 映像基址 / 文件偏移）

- **RVA** 是相对映像基址（ImageBase）的虚拟地址；本服务从不把 RVA 加上
  ImageBase 后再当文件偏移用。
- 头部区 RVA（`< SizeOfHeaders`）按 1:1 映射到磁盘头部。
- 节内 RVA：`文件偏移 = PointerToRawData + (RVA - VirtualAddress)`，且仅当
  差值小于 `SizeOfRawData`（真实磁盘字节）时有效。
- 差值落在 `[SizeOfRawData, VirtualSize)` 区间属于**虚拟零填充**，没有磁盘
  字节，读取一律报 `RVA_ZERO_FILL`。
- 重叠节 / 多重映射报 `RVA_AMBIGUOUS`；任何读取前先核验完整数据跨度
  （`SPAN_CROSSES_REGION` / `TRUNCATED`）。
- 查询任一 RVA 时会返回采用的节与换算步骤，或无法映射的具体原因。

## 安全限制（默认值，见 `src/limits.ts`）

文件 ≤ 64MB；节 ≤ 96；导入描述符 ≤ 1024；每个描述符 thunk ≤ 65536；
DLL 名 ≤ 260 字节；函数名 ≤ 512 字节。所有指针先映射再读取。

## 构建 / 测试 / 启动 / 演示

```bat
npm install
npm run build     :: 编译 TypeScript 到 dist/
npm test          :: 构建并运行全部测试（node:test）
npm run demo      :: 生成合成样本，演示导入清单与损坏指针定位
npm start         :: 启动 HTTP 服务（默认自动选择空闲端口）
```

指定端口与数据目录：

```bat
node dist/src/cli.js serve --port 8765 --data data
```

## CLI

```
node dist/src/cli.js import <file.pe> [--force]   导入并解析（生成报告）
node dist/src/cli.js files                        列出已导入文件
node dist/src/cli.js summary <fileId>             头部摘要
node dist/src/cli.js sections <fileId>            节表
node dist/src/cli.js imports <fileId>             导入清单
node dist/src/cli.js rva <fileId> 0x1000          解释 RVA 映射
node dist/src/cli.js reports                      列出报告
node dist/src/cli.js export <reportId> [out.json] 导出 JSON 报告
```

所有命令支持 `--data DIR`（默认 `./data`）。重复导入同一内容（按 SHA-256
判定）是确定性的：复用已有文件记录与最新报告，不重复解析；`--force` 强制重解析。
解析失败会落库为 `status=failed`（含错误码与文件偏移），绝不会登记为成功。

## HTTP API（默认 127.0.0.1，端口 0 = 自动选空闲端口）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/files` | body `{"path": "...", "force": false}`，导入并解析 |
| GET | `/files` | 已导入文件列表 |
| GET | `/files/:id/summary` | 头部摘要 |
| GET | `/files/:id/sections` | 节表 |
| GET | `/files/:id/imports` | 导入清单 |
| GET | `/files/:id/rva?rva=0x1000` | RVA 映射解释 |
| GET | `/reports` / `/reports/:id` | 报告列表 / 导出 JSON |

错误统一为 `{"error": {"code", "message", "fileOffset?", "rva?"}}`。

## 数据目录

`data/` 下保存：`pe-inspect.db`（SQLite，含解析器版本与报告）、
`files/`（导入文件的只读项目副本，权限 0444，附 SHA-256 与大小）。
服务重启后旧报告可直接查询。

## 测试

`test/pe.test.ts` 使用 `src/samplePe.ts` **按字节**构造最小 PE32+（节偏移与
导入名称预先写定），覆盖：正常名称导入、序号导入（bit 63 不丢失）、
thunk 回退、无导入、RVA≠文件偏移、虚拟零填充、重叠节、坏头位置、
截断字符串；并校验导入记录的每个字节区间都落在文件允许范围内
（直接按预写偏移读原始字节断言，不是生成器与解析器互证）。

## 已知限制

- 不解析延迟导入、绑定导入、导出表、资源、重定位、证书表。
- 节跨度按 `max(VirtualSize, SizeOfRawData)` 判定归属；磁盘可读部分仅以
  `SizeOfRawData` 为准。
- RVA 用 32 位无符号数处理（PE 规范上限 4GB 映像）。
