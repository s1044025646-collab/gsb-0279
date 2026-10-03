# PE32+ 导入表与 RVA 地址映射解析后端

离线、只读的 Windows **PE32+（64 位）** 普通导入表检查服务。仅提供 **HTTP API 与 CLI**，无前端。
不执行、不加载目标文件，不调用系统加载器，不打开或枚举系统上的真实 DLL，不依赖任何反汇编工具、Docker、WSL 或在线服务。

## 支持的 PE 子集

支持：
- DOS 头（`MZ`、`e_lfanew`）→ PE 签名（`PE\0\0`）→ COFF 头 → PE32+ 可选头（Magic `0x20b`）→ 节表。
- Machine 为 `IMAGE_FILE_MACHINE_AMD64 (0x8664)`。
- 普通导入目录（DataDirectory[1]）：按导入描述符读取直到全零终止项。
- 使用 `OriginalFirstThunk`（ILT）；当其为 0 时按规则回退到 `FirstThunk`（IAT），并给出 `THUNK_FALLBACK` 警告。
- 64 位 thunk：最高位 `0x8000000000000000` 表示**按序号导入**（低 16 位为序号），否则低 32 位为 hint/name 的 RVA。
- 名称导入：读取 2 字节 hint 与零终止 ASCII 函数名；DLL 名同为零终止 ASCII。
- 无导入目录（目录 RVA/大小为 0）视为**合法**状态。

明确不支持（会在 `unsupported`/`warnings` 中标注，或返回明确错误码）：
- 32 位 PE（PE32，Magic `0x10b`）、非 AMD64 架构 → `NOT_PE32_PLUS` / `UNSUPPORTED_MACHINE`。
- 延迟导入（DataDirectory[13]）→ 标记 `UNSUPPORTED_DELAY_IMPORT`，不解析。
- 绑定导入（描述符 `TimeDateStamp != 0`）→ 标记 `UNSUPPORTED_BOUND_IMPORT`，忽略绑定信息，仍按 thunk 解析。
- 不做机器码反汇编、病毒分析、数字签名校验、重定位/TLS/导出解析。

## 地址口径（RVA / ImageBase / 文件偏移）

- **RVA**：相对映像装入基址的虚拟偏移；本工具所有“目录/名称/thunk RVA”均为此口径。
- **ImageBase**：可选头中的首选映像基址（报告里以十六进制字符串输出），仅用于展示，不参与磁盘换算。
- **文件偏移**：磁盘字节位置。映射规则：
  1. `RVA < SizeOfHeaders`：头部区，按**恒等映射** `文件偏移 = RVA`（需磁盘确有这些字节）。
  2. RVA 落在某节 `[VirtualAddress, VirtualAddress+max(VirtualSize,SizeOfRawData))`：
     `delta = RVA - VirtualAddress`；当 `delta < SizeOfRawData` 时
     `文件偏移 = PointerToRawData + delta`，否则该地址属于**虚拟零填充（bss）**，磁盘无字节，禁止读取。
  3. 其余 RVA 无法映射。
- 每次读取前都先映射并**核验完整字节跨度**落在文件尺寸内，否则报 `BAD_RVA` / `TRUNCATED_READ` / `VIRTUAL_ZERO_FILL`。
- **重叠节/多重映射**：节表在虚拟区间或原始数据区间重叠会记录 `OVERLAPPING_SECTIONS` 警告；歧义 RVA（命中多个节）拒绝映射。

## 限制（可在 `src/pe/limits.ts` 调整）

| 项目 | 默认上限 |
| --- | --- |
| 文件大小 | 64 MiB |
| 节数量 | 96 |
| 导入描述符 | 4096 |
| 每 DLL thunk | 1,000,000 |
| DLL 名 / 函数名长度 | 1024 字节 |

## 环境要求

- Windows + Node.js **>= 22.5**（开发验证于 Node 25.5.0，使用内置 `node:sqlite`，无需本地编译依赖）。

## 安装、构建、测试

```powershell
npm install
npm run build      # tsc 编译到 dist/
npm test           # 编译并运行 node:test（15 个用例）
```

## 生成合成 PE 夹具并演示

合成夹具由 `test/builder.ts` + `test/fixtures.ts` **独立按字节构造**，节偏移与导入名称预先写死，不依赖本解析器。

```powershell
npm run fixtures   # 在 data/fixtures/ 生成 11 个最小 PE 文件
npm run demo       # 演示正常导入、RVA 解释、损坏指针定位
```

覆盖场景：正常名称导入、纯序号导入、thunk 回退、无导入、RVA≠文件偏移、虚拟零填充、重叠节、坏 PE 头位置、截断字符串、坏导入 RVA、缺少终止项、32 位 PE。

## CLI

编译后通过 `node dist/src/cli/index.js <命令>` 运行（或 `npm run cli -- <命令>`）。

```powershell
node dist/src/cli/index.js import <pe文件> [--name 名称]
node dist/src/cli/index.js reports
node dist/src/cli/index.js header <id>
node dist/src/cli/index.js sections <id>
node dist/src/cli/index.js imports <id> [--json]
node dist/src/cli/index.js map <id> <rva> [length] [--json]
node dist/src/cli/index.js export <id> [输出文件.json]
node dist/src/cli/index.js serve [--port 端口]   # 默认端口 0 = 自动选择空闲端口
node dist/src/cli/index.js demo
```

通用选项 `--data-dir <目录>` 指定数据目录（默认 `./data`）。整数支持十进制或 `0x` 十六进制。

示例：

```powershell
node dist/src/cli/index.js import data/fixtures/normal-name-import.exe
node dist/src/cli/index.js imports 1
node dist/src/cli/index.js map 1 0x20e0 2
node dist/src/cli/index.js export 1 report.json
```

## HTTP API

仅监听 `127.0.0.1`，返回 JSON。错误形如 `{ "error": { "code", "message", "fileOffset", "rva" } }`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/imports` | 体 `{"path": "<项目内相对或绝对路径>"}`；解析并登记。重复内容返回 `200 duplicated=true`，新文件 `201`。解析失败返回 `422`，**不写入成功报告** |
| GET | `/api/reports` | 报告列表与解析器版本入口 |
| GET | `/api/reports/:id` | 完整报告 |
| GET | `/api/reports/:id/header` | 头部摘要 |
| GET | `/api/reports/:id/sections` | 节表与重叠警告 |
| GET | `/api/reports/:id/imports` | 导入清单（DLL/函数/来源偏移） |
| GET | `/api/reports/:id/map?rva=0x..&length=n` | RVA→文件偏移解释（采用节、换算步骤或不可映射原因） |

`length` 允许 1..16；`rva` 支持十进制/`0x`。

```powershell
node dist/src/cli/index.js serve --port 8000
Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/imports -ContentType application/json `
  -Body '{"path":"data/fixtures/normal-name-import.exe"}'
```

## 持久化与确定性

- 数据目录 `./data`（可配置）：`reports.db`（SQLite，WAL）+ `files/<sha256>.bin` **只读项目副本**。
- 报告按 **SHA-256 去重**：同一位内容重复导入幂等，返回既有 id，不产生第二条记录。
- 仅**成功**解析会落库；失败（坏头、坏 RVA、截断等）不登记为成功。
- 保存解析器版本（`meta.parser_version` 与每条报告的 `parser_version`）。服务/进程重启后可继续查询历史报告（有测试覆盖）。

## 错误码

`FILE_TOO_LARGE`、`FILE_EMPTY`、`BAD_DOS_SIGNATURE`、`BAD_PE_OFFSET`、`BAD_PE_SIGNATURE`、
`TRUNCATED_HEADER`、`UNSUPPORTED_MACHINE`、`NOT_PE32_PLUS`、`UNSUPPORTED_OPTIONAL_MAGIC`、
`TOO_MANY_SECTIONS`、`TRUNCATED_SECTION_TABLE`、`INVALID_SECTION`、`OVERLAPPING_SECTIONS`、
`BAD_RVA`、`VIRTUAL_ZERO_FILL`、`TRUNCATED_READ`、`BAD_IMPORT_DIRECTORY`、
`IMPORT_MISSING_TERMINATOR`、`TOO_MANY_DESCRIPTORS`、`TOO_MANY_THUNKS`、`BAD_THUNK`、
`NAME_TOO_LONG`、`UNSUPPORTED_BOUND_IMPORT`、`UNSUPPORTED_DELAY_IMPORT`。

## 目录结构

```
src/pe/errors.ts    错误码与 PeError（携带 fileOffset/rva）
src/pe/limits.ts    上限与解析器版本
src/pe/reader.ts    带跨度核验的小端字节读取
src/pe/mapper.ts    RVA 映射（头部/节/零填充/重叠歧义）
src/pe/parser.ts    PE32+ 头、节表、导入目录与 thunk 解析
src/db.ts           SQLite 报告与只读副本
src/service.ts      领域服务
src/server.ts       HTTP API
src/cli/index.ts    CLI
test/builder.ts     独立按字节 PE 合成器
test/fixtures.ts    11 个最小场景夹具
test/parser.test.ts 测试（含重启、幂等、区间独立校验）
```
