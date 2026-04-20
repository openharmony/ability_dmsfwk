# Claude Code 项目规范

## Commit Message 格式（强制要求）

在提交代码时，**必须**使用以下格式：

```bash
<type>: <description>

Signed-off-by: m30043719 <maxiaodong25@huawei.com>

UserId：30043719

Co-Authored-By: Agent
```

### 类型说明
- `feat`: 新功能
- `fix`: 修复 bug
- `docs`: 文档更新
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建工具变动

### 重要提醒
**每次提交前，Claude 必须确认包含：**
1. ✅ Signed-off-by 行
2. ✅ UserId 行
3. ✅ Co-Authored-By 行

**如果用户要求多次提交但只想要一个 commit，使用：**
```bash
git commit --amend  # 非首次提交
```

## 编码规范

### 行长度限制
- **最大120字符/行**
- 超过120字符必须换行

### 禁止魔鬼数字
```cpp
// ❌ 错误
bufferSize = 1024;

// ✅ 正确
constexpr uint32_t DEFAULT_BUFFER_SIZE = 1024;
bufferSize = DEFAULT_BUFFER_SIZE;
```

**允许的数字**: 0, 1, -1（用于循环、判断等）

## 每次会话开始时

Claude 应该：
1. 首先读取本文件
2. 遵循以上规范
3. 提交代码前主动确认格式正确
