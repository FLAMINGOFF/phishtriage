# PhishTriage

[English](README.md) | **简体中文**

[![CI](https://github.com/FLAMINGOFF/phishtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/FLAMINGOFF/phishtriage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)

一个可自行部署的**可疑邮件上报与自动分析平台**：员工把可疑邮件以附件形式转发到上报邮箱，
PhishTriage 自动解析、分析、查询威胁情报，用可解释的规则打分，回信告诉上报人结果；
SOC 分析员在 Web 后台复核、改判定、导出 IOC。

> **状态：** v1.0.0。MVP 范围内的功能已全部完成；每个里程碑做了什么、每个设计决定的理由见 [PROGRESS.md](PROGRESS.md)。

## 演示

![员工上报可疑邮件，收到判定回信，分析员在后台查看证据](docs/images/demo.gif)

_员工通过邮件上报一封钓鱼邮件，几秒内 PhishTriage 回信告知判定和原因，分析员在后台能看到每条规则及其证据。所有数据都是合成的。_

## 为什么做这个

大学 SOC 每天都会收到大量“这是不是钓鱼邮件？”的上报。人工分诊又慢又不一致：
有人只看邮件头，有人只看链接，上报人要等好几个小时才有回复。PhishTriage 用几秒钟
把重复性的第一轮检查按同一标准做完，并把证据摆出来，分析员可以确认或推翻。

## 功能

- 三个上报入口：IMAP 上报邮箱、后台上传 `.eml`、REST API（`POST /api/reports`）。
- 稳健的邮件解析：以 `message/rfc822` 附件夹带的原始邮件、内联转发、各种字符集、格式错误的邮件头。
- 五类分析器（邮件认证、发件人、链接、附件、内容），以及带缓存和限速的威胁情报查询
  （VirusTotal、URLhaus、RDAP）。
- 可解释的打分：每个判定都列出规则 ID、分值和证据。
- 自动给组织内部的上报人回信，并有防滥用限制。
- 分析员后台：报告队列、详情页、改判定、备注、审计日志、IOC 导出（CSV、STIX 2.1）、统计页。
- 数据保留：原始邮件和附件 90 天后自动删除，判定和 IOC 保留。
- 一条命令跑起带合成数据的演示；另有评估脚本，可在带标签的邮件集上算准确率。

## 架构

```mermaid
flowchart LR
    subgraph intake[上报入口]
        mailbox[(上报邮箱<br/>IMAP)] --> poller
        upload[上传 .eml] --> web
        api[POST /api/reports] --> web
    end
    poller -->|报告 ID| queue[(Redis 队列)]
    web -->|报告 ID| queue
    queue --> worker
    worker -->|解析 · 分析 · 打分| db[(PostgreSQL)]
    worker -->|只查哈希和 URL| intel[VirusTotal · URLhaus · RDAP]
    worker -->|判定回信| smtp[SMTP 发给上报人]
    analyst((分析员)) --> web
    web -->|读取| db
```

| 进程 | 职责 |
| --- | --- |
| `web` | FastAPI：分析员后台、`.eml` 上传、REST API、登录。从不解析邮件内容。 |
| `worker` | RQ worker：解析 → 分析 → 情报查询 → 打分 → 回信；每天的数据保留清理。 |
| `poller` | 每 30 秒轮询一次 IMAP 上报邮箱，把新上报放进队列。 |
| `db` / `redis` | PostgreSQL 16 存报告和证据；Redis 7 做队列、缓存和限速。 |
| `greenmail` / `mailpit` | 本地上报邮箱和回信收件箱，只用于开发和演示。 |

一份上报怎样在这些进程之间流转、数据模型、数据保留任务，见 [docs/architecture.md](docs/architecture.md)（英文）。

## 打分规则

五个分析器按固定的规则 ID 报告命中；每条规则有分值和证据（检查了哪个字段、原值、匹配到什么）。
每条规则每封邮件最多计一次，分数相加后映射成判定。完整规则表和细节见 [docs/scoring.md](docs/scoring.md)（英文）。

| 判定 | 条件 | 规则举例 |
| --- | --- | --- |
| 恶意 | ≥ 70，或命中任一 `*_INTEL_MALICIOUS` | `ATT_EXECUTABLE` 40、`SENDER_LOOKALIKE_DOMAIN` 30 |
| 可疑 | 40–69 | `AUTH_DMARC_FAIL` 30、`URL_CREDENTIAL_FORM` 25 |
| 低风险 | 15–39 | `URL_IP_HOST` 15、`CONTENT_CREDENTIAL_REQUEST` 15 |
| 未发现问题 | < 15 | `URL_SHORTENER` 5、`CONTENT_URGENCY` 5 |

分值写在 `app/scoring/rules.yaml` 里，调分不用改代码。回信永远不说邮件“安全”。

## 威胁情报

worker 在 VirusTotal 上查附件哈希和 URL，在 URLhaus 上查 URL 和主机，用 RDAP 查发件域名的注册时间，
然后拿这些结果跑规则。API key 是可选的：没配时这些查询记为 `skipped`，其他功能照常。结果缓存在
Redis 里（VirusTotal 24 小时、URLhaus 1 小时）；VirusTotal 受免费额度约束：所有 worker 共用一个令牌桶
（任意 60 秒内最多 4 次，测试里用假时钟证明），另有每天 500 次的预算。细节、状态含义和配置项见
[docs/intel.md](docs/intel.md)（英文）。

## 分析员后台

分析员登录后台（账号用 `python -m app.cli create-user` 创建），在报告队列里按判定、状态和是否已复核筛选。
报告详情页显示判定、每条命中规则及其证据、去活后的 IOC 和情报结果、附件、Authentication-Results、
Received 链路、纯文本正文，以及放在沙箱 iframe 里的清洗后 HTML 正文。分析员可以改判（保留原始分数）、
写备注、重新分析、把附件下载成密码为 `infected` 的加密 zip，并把 IOC 导出为 CSV 或 STIX 2.1 bundle。
登录、改判、备注、下载和导出都会写进审计日志，管理员可以在后台查看。统计页显示每周上报数、判定分布、
出结果所需时间，以及分析员有多少次推翻了规则的判定。细节见 [docs/console.md](docs/console.md)（英文）。

## 上报邮箱与自动回信

员工把可疑邮件以附件形式转发到上报邮箱。poller 通过 IMAP 取新邮件（读取时不标记为已读），
按 Message-ID 跳过已处理过的，放进队列后移到 `Processed` 文件夹。worker 得出判定后给上报人
回一封纯文本邮件：判定结果、该怎么做、主要原因。只回复本组织域名下的地址，而且组织自己的邮件
服务器要记录该上报邮件通过了 DMARC，这样谁也没法借 PhishTriage 给第三方发邮件；每个上报人
每小时最多收到 20 封回信。内联转发的邮件同样会分析，回信里会提醒下次用“以附件形式转发”。
细节见 [docs/mailbox.md](docs/mailbox.md)（英文）。

## 安全设计

每封上报邮件都当成攻击者可控的输入。要点如下（完整的 STRIDE 威胁模型，以及每项措施对应的代码和测试，见
[docs/threat-model.md](docs/threat-model.md)，英文）：

- 服务器从不访问邮件里的链接，也从不渲染邮件的原始 HTML。
- 附件绝不执行、绝不上传到任何地方，只查询哈希；URL 只查询，不提交扫描。
- Web 进程从不解析邮件，解析只在 worker 里做。worker 的 HTTP 客户端只能访问写死的情报域名
  （只走 HTTPS、不跟随跳转），邮件内容没法让它去请求别的地址。
- 压缩包只读目录、不解压；邮件大小和嵌套层数有严格上限。
- 回信只发给本组织域名下、且通过 DMARC 验证的上报人（每人每小时最多 20 封），内容是固定模板的纯文本，
  被举报邮件的主题会先去活再写进去，所以没人能借平台给别人发垃圾邮件或链接。
- 后台：argon2id 存密码，服务端会话配 HttpOnly/SameSite cookie，所有表单带 CSRF token，
  同一账号 15 分钟内失败 5 次就锁定，严格的 CSP（不允许内联脚本），所有攻击者可控的字符串都转义显示。
- 密钥只从环境变量读取；策略文件遇到未知字段直接报错。
- 原始邮件、附件和正文 90 天后自动删除（可配置）。
- CI 跑 ruff、mypy、SQLite 和 PostgreSQL 上的测试、pip-audit、gitleaks、Trivy 镜像扫描，以及对整套 Compose 服务的端到端邮件测试。
- 容器以非特权用户运行，根文件系统只读，去掉所有 Linux capabilities；演示端口只绑定 `127.0.0.1`。

## 快速开始

需要：Docker（含 Compose v2）。

```bash
git clone https://github.com/FLAMINGOFF/phishtriage.git
cd phishtriage
cp .env.example .env          # 演示可以不配；要填 API key 时需要
docker compose up --build --wait
curl http://localhost:8000/healthz   # {"status":"ok"}
curl http://localhost:8000/readyz    # 检查数据库和 Redis
docker compose exec web python -m app.cli create-user admin@example.edu --role admin
```

最后一条命令会让你为第一个后台账号设置密码（至少 12 个字符）。

| 地址 | 内容 |
| --- | --- |
| http://localhost:8000 | PhishTriage 分析员后台（用刚建的账号登录） |
| http://localhost:8025 | Mailpit：查看 PhishTriage 发出的回信 |

用合成样例邮件试一下：

- 像员工那样用邮件上报：把 `samples/` 里的每封样例发到上报邮箱（GreenMail），并等待
  PhishTriage 的回信（回信会出现在 Mailpit 里）：

  ```bash
  python3 scripts/send_sample.py --wait 90
  # sent credential-phish.eml as <...@example.edu>
  # ...
  # reply for credential-phish.eml: [PhishTriage] Malicious: Action required: verify your account
  ```

  打开 http://localhost:8025 看回信，打开 http://localhost:8000/reports 看报告。
  加上 `--from outsider@external.example` 可以验证外部地址的上报不会收到回信。
- 给报告队列和统计页加点历史数据：`docker compose run --rm seed` 会把 150 份样例上报跑一遍真实的分析流程，
  时间分布在最近 12 周，并模拟一位演示分析员的复核（`scripts/seed_demo.py`；不会发回信）。
- 网页上传：登录后打开 http://localhost:8000/upload ，选择 `tests/fixtures/emails/` 里的任意一封。
  报告页会等 worker 处理完，然后显示判定、证据和情报结果；http://localhost:8000/reports 是报告队列。
- REST API：在 `.env` 里设置 `API_TOKEN`（至少 32 个字符），重启后提交并等待判定
  （脚本会轮询 `GET /api/reports/{id}`，直到 worker 处理完）：

  ```bash
  API_TOKEN=... python3 scripts/submit_report.py \
      tests/fixtures/emails/02_html_link_mismatch_b64.eml
  ```

  API 本身返回 `202 Accepted` 和报告 ID，分析在 worker 里异步进行。
- 命令行（不需要启动服务，也不联网）：`uv run python -m app.cli analyze
  tests/fixtures/emails/06_report_with_attached_original.eml --wrapper` 输出 JSON。
- 威胁情报：在 `.env` 里填 `VT_API_KEY` 和/或 `URLHAUS_AUTH_KEY`，然后重启 worker
  （`docker compose up -d worker`）。演示样例只用保留域名，查询结果是“查不到”，这是正常的。

### 本地开发

```bash
uv sync                     # 按 uv.lock 安装 Python 3.12 和全部依赖
uv run pre-commit install   # 每次提交自动跑 ruff、mypy、gitleaks
uv run pytest               # 测试从不联网（respx 会拦住所有请求）
uv run pytest -m live tests/live   # 可选：真实调用情报接口，需要你自己的 key
# 可选：对 `API_TOKEN=... docker compose up` 起来的整套服务跑端到端测试（见 docs/mailbox.md）
PHISHTRIAGE_BASE_URL=http://127.0.0.1:8000 PHISHTRIAGE_API_TOKEN=... uv run pytest -m integration tests/integration
uv run ruff check . && uv run ruff format --check . && uv run mypy app
uv run python -m app.cli check-config
uv run python scripts/generate_emails.py           # 重新生成样例邮件
UPDATE_SNAPSHOTS=1 uv run pytest tests/unit/test_snapshots.py   # 改了解析逻辑之后更新快照
TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost/test uv run pytest  # 在 PostgreSQL 上跑
```

`tests/fixtures/emails/` 里的 14 封样例邮件由 `scripts/generate_emails.py` 生成，只用保留域名
（`example.com`、`example.edu`、`.example`、`.test`）。覆盖 quoted-printable 和 base64 正文、
GBK 和 ISO-2022-JP、格式错误的邮件头、以 `message/rfc822` 或 `.eml` 文件附带的原始邮件、
内联转发、仿冒域名和 punycode、数字 IP 主机、短链接、双扩展名、文件名里的从右到左覆盖字符，
以及伪造的认证结果头。

## 评估

`scripts/evaluate.py` 离线跑规则，输出精确率、召回率、误报率、混淆矩阵、阈值扫描和每条规则的命中率。
“阳性”指判定为恶意或可疑；目标是召回率 ≥ 90%、误报率 ≤ 5%。

| 数据 | 邮件数 | 精确率 | 召回率 | 误报率 |
| --- | --- | --- | --- | --- |
| 合成样例（`tests/fixtures/emails/`） | 10 封钓鱼、5 封正常 | 100% | 100% | 0% |
| Nazario 2021 + SpamAssassin ham（默认策略、离线） | 101 封钓鱼、2,750 封正常 | 6.25% | 2.97% | 1.64% |
| 同一公开语料（固定品牌策略、离线） | 101 封钓鱼、2,750 封正常 | 6.00% | 2.97% | 1.71% |

合成样例是和规则一起写的，100% 只说明回归测试通过，不代表真实环境的准确率。方法、在公开语料上运行的命令，
以及实测结果见 [docs/evaluation.md](docs/evaluation.md)（英文）。

**公开语料的召回率未达标：** 两种策略都只检出 101 封钓鱼邮件中的 3 封。评估流程运行成功不等于检测能力达标；这批历史邮件的离线结果不能证明生产环境效果。文档记录了来源校验值、混淆矩阵、漏报与误报模式，并提供[可复现的 Actions 运行](https://github.com/FLAMINGOFF/phishtriage/actions/runs/45516152754)。

## 局限与路线图

- 没有动态沙箱：不打开链接，不运行附件。
- 不从全员邮箱批量删除同类邮件（需要邮件系统管理员权限）。
- 开发和演示都用本地邮件服务器，不接入真实的 Microsoft 365 或 Google Workspace 租户。
- VirusTotal 免费 API（每分钟 4 次、每天 500 次）只能用于非商业用途；真正部署到机构需要付费授权。
- 回信规则信任组织邮件服务器写入的 DMARC 结果，所以这台服务器必须删除外来邮件里伪造的
  `Authentication-Results` 头（见 [docs/mailbox.md](docs/mailbox.md)）。
- 后台还没有双因素认证。

后续可以做：把多份上报归成同一波攻击（“已有 12 人上报”）、Outlook 或 Gmail 的一键上报按钮、用 OAuth2
接入 Microsoft 365 或 Gmail 测试邮箱、通过 urlscan.io 非公开扫描查看落地页截图、把确认的 IOC 推送到 MISP、
用 YARA 扫描附件、判定为恶意时推送到 Slack 或 Teams。

## 许可证

[MIT](LICENSE)
