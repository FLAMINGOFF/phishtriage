# PhishTriage

[English](README.md) | **简体中文**

[![CI](https://github.com/FLAMINGOFF/phishtriage/actions/workflows/ci.yml/badge.svg)](https://github.com/FLAMINGOFF/phishtriage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)

一个可自行部署的**可疑邮件上报与自动分析平台**：员工把可疑邮件以附件形式转发到上报邮箱，
PhishTriage 自动解析、分析、查询威胁情报，用可解释的规则打分，回信告诉上报人结果；
SOC 分析员在 Web 后台复核、改判定、导出 IOC。

> **状态：** 开发中。已完成 M0（项目骨架）、M1（邮件解析与 IOC 提取）。进度见 [PROGRESS.md](PROGRESS.md)。

## 演示

_“发送上报 → 收到回信 → 后台详情页”的演示 GIF 在 M6 加入。_

## 为什么做这个

大学 SOC 每天都会收到大量“这是不是钓鱼邮件？”的上报。人工分诊又慢又不一致：
有人只看邮件头，有人只看链接，上报人要等好几个小时才有回复。PhishTriage 用几秒钟
把重复性的第一轮检查按同一标准做完，并把证据摆出来，分析员可以确认或推翻。

## 功能

v1.0 计划包含（已完成的部分见 [PROGRESS.md](PROGRESS.md)）：

- 三个上报入口：IMAP 上报邮箱、后台上传 `.eml`、REST API（`POST /api/reports`）。
- 稳健的邮件解析：以 `message/rfc822` 附件夹带的原始邮件、内联转发、各种字符集、格式错误的邮件头。
- 五类分析器（邮件认证、发件人、链接、附件、内容），以及带缓存和限速的威胁情报查询
  （VirusTotal、URLhaus、RDAP）。
- 可解释的打分：每个判定都列出规则 ID、分值和证据。
- 自动给组织内部的上报人回信，并有防滥用限制。
- 分析员后台：报告队列、详情页、改判定、备注、审计日志、IOC 导出（CSV、STIX 2.1）、统计页。

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
| `worker` | RQ worker：解析 → 分析 → 情报查询 → 打分 → 回信。 |
| `poller` | 每 30 秒轮询一次 IMAP 上报邮箱，把新上报放进队列。 |
| `db` / `redis` | PostgreSQL 16 存报告和证据；Redis 7 做队列、缓存和限速。 |
| `greenmail` / `mailpit` | 本地上报邮箱和回信收件箱，只用于开发和演示。 |

## 打分规则

_M2 完成后详见 `docs/scoring.md`。_ 简单说：每条规则有固定的 ID、分值和证据；总分对应
*恶意*（≥ 70 或命中任一威胁情报）、*可疑*（40–69）、*低风险*（15–39）、*未发现问题*（< 15）。
回信永远不说邮件“安全”。

## 安全设计

每封上报邮件都当成攻击者可控的输入。要点如下（完整的 STRIDE 威胁模型见 M6 的
`docs/threat-model.md`）：

- 服务器从不访问邮件里的链接，也从不渲染邮件的原始 HTML。
- 附件绝不执行、绝不上传到任何地方，只查询哈希。
- 压缩包只读目录、不解压；邮件大小和嵌套层数有严格上限。
- 密钥只从环境变量读取；策略文件遇到未知字段直接报错。
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
```

| 地址 | 内容 |
| --- | --- |
| http://localhost:8000 | PhishTriage Web（M4 起是分析员后台） |
| http://localhost:8025 | Mailpit：查看 PhishTriage 发出的回信 |

用合成样例邮件试一下解析：

- 网页上传：打开 http://localhost:8000/upload ，选择 `tests/fixtures/emails/` 里的任意一封。
- REST API：在 `.env` 里设置 `API_TOKEN`（至少 32 个字符），重启后运行

  ```bash
  curl -H "Authorization: Bearer $API_TOKEN" -H "Content-Type: message/rfc822" \
       --data-binary @tests/fixtures/emails/02_html_link_mismatch_b64.eml \
       http://localhost:8000/api/reports
  ```

- 命令行（不需要启动服务）：`uv run python -m app.cli analyze
  tests/fixtures/emails/06_report_with_attached_original.eml --wrapper` 输出 JSON。

通过邮件发送样例上报的脚本（`scripts/send_sample.py`）在 M5 加入。

### 本地开发

```bash
uv sync                     # 按 uv.lock 安装 Python 3.12 和全部依赖
uv run pre-commit install   # 每次提交自动跑 ruff、mypy、gitleaks
uv run pytest               # 测试从不联网
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

_在带标签的数据集上的精确率和召回率在 M6 给出（`docs/evaluation.md`）。_

## 局限与路线图

- 没有动态沙箱：不打开链接，不运行附件。
- 不从全员邮箱批量删除同类邮件（需要邮件系统管理员权限）。
- 开发和演示都用本地邮件服务器，不接入真实的 Microsoft 365 或 Google Workspace 租户。
- VirusTotal 免费 API（每分钟 4 次、每天 500 次）只能用于非商业用途；真正部署到机构需要付费授权。

## 许可证

[MIT](LICENSE)
