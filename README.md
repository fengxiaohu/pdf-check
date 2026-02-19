**[English](README_EN.md)** | **简体中文**

# pdf-check

`pdf-check` 是一个静态 PDF 安全扫描工具，重点检测：
- LLM 指令 / Prompt Injection 文本
- 隐藏文本与可疑链接 / 动作
- 嵌入内容与结构异常

项目同时提供本地 Web 页面，用户上传 PDF 后即可检测，并下载清洗后的 Markdown / PDF。

## 安全边界

本项目仅执行静态分析，不会：
- 执行 JavaScript
- 自动打开外部链接
- 按 PDF 内容触发系统命令

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CLI 用法

### 1) Sanitizer

```bash
python pdf_sanitizer.py input.pdf --out report.json --extract output/ --verbose
python pdf_sanitizer.py input.pdf --json
python pdf_sanitizer.py input.pdf --strict
python pdf_sanitizer.py --clean-artifacts --clean-dir .
```

参数：
- `--json`：输出机器可读 JSON
- `--out <path>`：写入 JSON 报告文件
- `--extract <dir>`：导出可疑对象原始数据
- `--strict`：更激进阈值
- `--verbose`：输出更多证据
- `--clean-artifacts`：清理生成产物并退出
- `--clean-dir <path>`：清理基目录

退出码：
- `0`：无高危触发项
- `1`：存在高危触发项
- `2`：处理失败

### 2) LLM 指令扫描

```bash
python -m pdf_check.cli /path/to/file.pdf --json
python -m pdf_check.cli /path/to/file.pdf --llm-strict
python -m pdf_check.cli /path/to/file.pdf --llm-keywords custom_rules.yaml --json
```

## Web 页面

启动：

```bash
python -m pdf_check.web_app
```

打开：
- `http://127.0.0.1:5000`

功能：
- 上传 PDF 后进行静态扫描
- 展示风险摘要与明细
- 下载清洗结果：`Clean Markdown` / `Clean PDF`

## 测试

```bash
pytest -q
```

## 许可证

本项目采用 **MIT License**。
详见：`LICENSE`
