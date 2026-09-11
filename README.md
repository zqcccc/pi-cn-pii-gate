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

## 与 pi-privacy 的关系

两者完全兼容、叠加工作：

- pi-privacy：真实邮箱、API key/token、美国 SSN/信用卡
- cn-pii-gate：中国手机号、身份证、银行卡、自定义名字

顺序无关，两个处理器各自打码自己识别的模式。

## License

MIT
