// cn-pii-gate —— 中国版 PII 门控扩展（通用发布版）
//
// 补充 pi-privacy 检测不到的中国常见个人敏感信息，发送前自动打码：
//   - 中国手机号：1[3-9]\d{9}（11 位连续数字，1 开头）
//   - 身份证号：17 位数字 + 数字/X（18 位）
//   - 银行卡号：13-19 位连续数字（Luhn 校验通过才打码，避免误伤订单号/日期）
//   - 自定义敏感名字（拼音/中文，从配置文件或环境变量读取，见下方"配置"）
//
// 自动路由（可选）：检测到敏感信息时，把本次请求的 model 切换为
// SAFE_MODEL（默认火山方舟 doubao，供应商看不到请求内容）。
// 没有敏感内容则保持原模型，下一轮自动恢复。路由是"单次请求"级别。
//
// ── 配置（三选一，优先级从低到高）──
//   1. 代码默认值（下方 DEFAULT_CONFIG）
//   2. 配置文件：CN_PII_CONFIG=<path>，或运行时目录下 cn-pii-gate.config.json
//      {
//        "names": ["zhaoqiaochu", "赵巧楚"],
//        "safeModel": "doubao-seed-2-1-pro-260628",
//        "routeEnabled": true
//      }
//   3. 环境变量（覆盖文件）：
//      CN_PII_NAMES="zhaoqiaochu,赵巧楚"
//      CN_PII_SAFE_MODEL="doubao-seed-2-1-pro-260628"
//      CN_PII_ROUTE="true|false"
//
// 与 pi-privacy 完全兼容：挂同一个 before_provider_request 事件，
// 采用相同的"返回新 payload"协议。打码在本地完成，不经过任何模型。

import { readFileSync, existsSync } from "node:fs";

const DEFAULT_CONFIG = {
  names: [] as string[], // 用户敏感名字（拼音小写 / 中文原文），发布版默认为空
  safeModel: "doubao-seed-2-1-pro-260628", // 安全模型（火山方舟 doubao）
  routeEnabled: true, // 是否启用自动路由
};

type Config = typeof DEFAULT_CONFIG;

function loadConfig(): Config {
  const cfg: Config = { ...DEFAULT_CONFIG, names: [...DEFAULT_CONFIG.names] };

  // 1. 配置文件
  const explicit = process.env.CN_PII_CONFIG?.trim();
  const cwd = process.cwd();
  const path = explicit && explicit.length ? explicit : `${cwd}/cn-pii-gate.config.json`;
  try {
    if (existsSync(path)) {
      const file = JSON.parse(readFileSync(path, "utf8"));
      if (Array.isArray(file.names)) cfg.names = file.names.map(String);
      if (typeof file.safeModel === "string" && file.safeModel) cfg.safeModel = file.safeModel;
      if (typeof file.routeEnabled === "boolean") cfg.routeEnabled = file.routeEnabled;
    }
  } catch {
    // 配置文件不可读时静默使用默认值
  }

  // 2. 环境变量覆盖
  const envNames = process.env.CN_PII_NAMES?.trim();
  if (envNames) cfg.names = envNames.split(/[,，]/).map((s) => s.trim()).filter(Boolean);
  if (process.env.CN_PII_SAFE_MODEL?.trim()) cfg.safeModel = process.env.CN_PII_SAFE_MODEL.trim();
  if (process.env.CN_PII_ROUTE !== undefined) cfg.routeEnabled = /^(1|true|yes|on)$/i.test(process.env.CN_PII_ROUTE);

  return cfg;
}

const MASK = {
  phone: "«cn-phone»",
  id: "«cn-id»",
  card: "«cn-card»",
  name: "«cn-name»",
};

// 中国手机号：1[3-9] 开头 + 9 位数字，前后不能是数字（避免截断 18 位身份证）
const PHONE_RE = /(?<!\d)1[3-9]\d{9}(?!\d)/g;

// 身份证号：18 位，17 位数字 + 末位数字或 X/x
const ID_RE = /(?<!\d)(?:\d{17}[\dXx])(?!\d)/g;

// Luhn 校验（银行卡识别，避免误伤订单号/日期串）
function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function maskCard(s: string): string {
  return s.replace(/(?<!\d)\d{13,19}(?!\d)/g, (m) => (luhnValid(m) ? MASK.card : m));
}

// 名字匹配：拼音忽略大小写，允许 "zhao qiao chu" / "zhao-qiao-chu" 变体
function buildNameRe(names: string[]): RegExp {
  const parts = names.map((n) => {
    const esc = n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (/^[a-z]+$/.test(n)) {
      const letters = [...esc].join("[\\s-]*");
      return letters;
    }
    return esc;
  });
  if (parts.length === 0) return /(?!)ä/; // 永不匹配
  return new RegExp(`(?<![\\p{L}\\p{N}])(${parts.join("|")})(?![\\p{L}\\p{N}])`, "giu");
}

function maskText(s: string, nameRe: RegExp): string {
  if (!s) return s;
  let out = s;
  out = out.replace(PHONE_RE, MASK.phone);
  out = out.replace(ID_RE, MASK.id);
  out = maskCard(out);
  out = out.replace(nameRe, MASK.name);
  return out;
}

function maskMessages(messages: any[], nameRe: RegExp): any[] {
  return messages.map((m: any) => {
    if (typeof m?.content === "string") {
      return { ...m, content: maskText(m.content, nameRe) };
    }
    if (Array.isArray(m?.content)) {
      return {
        ...m,
        content: m.content.map((p: any) =>
          typeof p?.text === "string" ? { ...p, text: maskText(p.text, nameRe) } : p,
        ),
      };
    }
    return m;
  });
}

export default function cnPiiGate(pi: any): void {
  const cfg = loadConfig();
  const nameRe = buildNameRe(cfg.names);

  pi.on("before_provider_request", async (event: any) => {
    const payload = event?.payload;
    if (!payload || typeof payload !== "object" || !Array.isArray(payload.messages)) {
      return undefined;
    }

    const all = JSON.stringify(payload.messages);
    const hasPhone = PHONE_RE.test(all);
    const hasId = ID_RE.test(all);
    const hasCard = /(?<!\d)\d{13,19}(?!\d)/g.test(all);
    const hasName = nameRe.test(all);

    const hasSensitive = hasPhone || hasId || hasCard || hasName;
    if (!hasSensitive) return undefined;

    const masked = maskMessages(payload.messages, nameRe);
    const maskedJson = JSON.stringify(masked);

    // 1) 总是打码
    let out: any = { ...payload, messages: masked };

    // 2) 自动路由（可选）：当前模型不是安全模型时，切到安全模型
    const currentModel = String(payload?.model ?? "");
    if (cfg.routeEnabled && !currentModel.startsWith("doubao-")) {
      out = { ...out, model: cfg.safeModel };
      console.error(
        `⚑ [cn-pii-gate] 检测到敏感信息，本次请求已自动路由 ${currentModel} → ${cfg.safeModel}（安全模型）`,
      );
    }

    // 内容没变化且没改模型 → 不返回（避免无意义重发）
    if (maskedJson === JSON.stringify(payload.messages) && out.model === payload.model) {
      return undefined;
    }
    return out;
  });
}
