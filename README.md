# cn-pii-gate

中国版 PII 门控扩展（Pi extension）。补充 [pi-privacy](https://www.npmjs.com/package/pi-privacy) 检测不到的中国常见个人敏感信息，发送前自动打码，并可自动路由到指定安全模型。

## 特性

- **中国手机号**（`1[3-9]` 开头 11 位）→ `«cn-phone»`
- **身份证号**（18 位含 X）→ `«cn-id»`
- **银行卡号**（13-19 位，Luhn 校验，不误伤订单号/日期）→ `«cn-card»`
- **自定义敏感名字**（拼音/中文，忽略大小写、容忍空格/连字符变体）→ `«cn-name»`
- **自动路由**（可选）：检测到敏感信息时，本次请求自动切换到安全模型（默认火山方舟 doubao，供应商看不到请求内容）；无敏感时保持原模型，下一轮自动恢复

打码在本地完成，不经过任何模型。

## 安装

```bash
pi install npm:cn-pii-gate
```

## 配置

### 方式一：配置文件（推荐）

在运行目录放 `cn-pii-gate.config.json`，或设置 `CN_PII_CONFIG=<path>` 指向任意位置：

```json
{
  "names": ["zhaoqiaochu", "赵巧楚"],
  "safeModel": "doubao-seed-2-1-pro-260628",
  "routeEnabled": true
}
```

### 方式二：环境变量

```bash
export CN_PII_NAMES="zhaoqiaochu,赵巧楚"
export CN_PII_SAFE_MODEL="doubao-seed-2-1-pro-260628"
export CN_PII_ROUTE="true"
```

环境变量优先于配置文件。

## 自动路由说明

| 情况 | 行为 |
|---|---|
| 请求含敏感信息 | 自动切到安全模型（`safeModel`） |
| 请求无敏感信息 | 保持原模型 |
| 下一轮无敏感 | 自动回到原模型 |

路由是"单次请求"级别，不是永久切换。切换时终端会打印一行提示。

## v0.1.2 修复说明

- **修复路由无法恢复**：此前路由判定扫描整个 messages（含历史），一旦历史里出现敏感串，后续所有请求都会一直路由到安全模型。现在**打码仍全量执行**（历史敏感内容始终对供应商不可见），但**路由只判定本轮新增内容**（最后一条 user 消息及之后的工具调用/结果），无敏感时自动回到原模型。

## v0.1.1 修复说明

- **修复误路由**：此前检测基于整个 payload 的 JSON 字符串，`timestamp`（13 位毫秒时间戳）会被银行卡正则误判，导致每次请求都自动路由到安全模型。现在检测只针对消息文本内容，且银行卡检测与打码统一使用 Luhn 校验（检测/打码完全一致）。
- 消除模块级共享正则 `lastIndex` 状态污染（多次请求间可能误判）。

## 与 pi-privacy 的关系

两者完全兼容、叠加工作：

- pi-privacy：真实邮箱、API key/token、美国 SSN/信用卡
- cn-pii-gate：中国手机号、身份证、银行卡、自定义名字

顺序无关，两个处理器各自打码自己识别的模式。

## License

MIT
