# NodeSeek 每日签到与随机评论

每天北京时间 00:17 由 GitHub Actions 自动执行，也可在 Actions 中手动 Run workflow。
先固定领取 5 鸡腿，再在交易区随机选择一个可评论帖子，发布一条随机祝福。
不再批量评论 20 个帖子，不额外给帖子加鸡腿。

## Secrets

在 Settings → Secrets and variables → Actions 保存：
- `NS_USERNAME`：NodeSeek 用户名
- `NS_PASSWORD`：NodeSeek 密码
- `YESCAPTCHA_KEY`：YesCaptcha API 密钥
- `COOKIE_ENCRYPTION_KEY`：专用 Fernet 加密密钥，不应删除或随意更换
- `NS_COOKIE`：可选，有效 Cookie 优先使用；失效时重新登录

首次运行没有 Cookie 时使用账号密码登录。之后优先读取 `.state/nodeseek.enc` 中的加密 Cookie，失效后才重新登录。
新 Cookie 用专用 Secret 加密后立即写回仓库，并重新读取、建立 Cookie 会话后继续签到。
写回使用工作流的 `GITHUB_TOKEN`（仅需 contents: write），无需个人访问令牌。
当天已评论或提交状态不明时不会重复发送。

用户名密码登录通过 YesCaptcha Turnstile 服务，可能消耗服务余额。
密码、API 密钥和 Cookie 不写入代码、日志或公开文件。

## 评论设置

默认每次运行最多评论一次，跳过置顶、只读及标题标有已出/已收的帖子。
默认随机文字为：帮顶一下，祝早日成交；支持一下，祝交易顺利；帮顶，祝早日找到合适的买家或卖家。
可用仓库变量 `NS_COMMENT_TEXTS` 自定义，例如：
```json
["帮顶一下，祝早日成交。", "支持一下，祝交易顺利。"]
```
评论应遵守论坛版规。手动重复运行可能产生额外评论。
如要仅签到，将工作流的 `NS_COMMENT` 改为 `"false"`。

## 验证

工作流只有在签到和评论均确认成功时显示绿色；提交评论后状态不明时不会再次发送。
GitHub 定时任务可能延迟，公开仓库长期无活动时平台可能暂停定时执行。
