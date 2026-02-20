<a id="readme-top"></a>

**[English](README_EN.md)** | **简体中文**

<br />
<div align="center">
  <h1 align="center">pdf-check</h1>
  <p align="center">
    静态 PDF 安全扫描器：检测隐藏文本、可疑链接/动作、Prompt Injection，并提供清洗导出。
    <br />
    <a href="https://github.com/fengxiaohu/pdf-check"><strong>查看仓库 »</strong></a>
    <br />
    <br />
    <a href="https://github.com/fengxiaohu/pdf-check/issues">反馈问题</a>
    ·
    <a href="https://github.com/fengxiaohu/pdf-check/issues">功能建议</a>
  </p>
</div>

<div align="center">

![CI](https://github.com/fengxiaohu/pdf-check/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/fengxiaohu/pdf-check)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

</div>

## 目录

- [关于项目](#关于项目)
  - [核心能力](#核心能力)
  - [技术栈](#技术栈)
- [快速开始](#快速开始)
  - [前置要求](#前置要求)
  - [安装](#安装)
- [使用方式](#使用方式)
  - [CLI: Sanitizer](#cli-sanitizer)
  - [CLI: LLM 指令扫描](#cli-llm-指令扫描)
  - [Web UI](#web-ui)
- [威胁模型与边界](#威胁模型与边界)
- [路线图](#路线图)
- [贡献](#贡献)
- [许可证](#许可证)
- [联系方式](#联系方式)
- [致谢](#致谢)

## 关于项目

`pdf-check` 用于对不可信 PDF 进行**静态安全分析**，覆盖以下风险面：
- 隐藏文本（透明文本、极小字体、Tr=3、控制字符混淆）
- 可疑链接与动作（`/OpenAction`, `/JavaScript`, `/URI`, `/Launch`, `/GoToR`, `/SubmitForm`）
- 嵌入内容（`EmbeddedFiles`、可疑流）
- LLM 定向指令与 prompt-injection 文本

### 核心能力

- PDF 结构扫描 + 页面内容流分析
- 风险分级（high / medium / low）与可审计证据输出
- JSON 输出、提取模式（`--extract`）、严格模式（`--strict`）
- Web 上传检测 + 清洗结果下载（Markdown / PDF）

### 技术栈

- Python 3.10+
- `pikepdf`
- `pypdf`
- `Flask`
- `pytest`
- `reportlab`

<p align="right">(<a href="#readme-top">回到顶部</a>)</p>

## 快速开始

### 前置要求

```bash
python --version
# 建议 >= 3.10
```

### 安装

```bash
git clone https://github.com/fengxiaohu/pdf-check.git
cd pdf-check
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

<p align="right">(<a href="#readme-top">回到顶部</a>)</p>

## 使用方式

### CLI: Sanitizer

```bash
python pdf_sanitizer.py input.pdf --out report.json --extract output/ --verbose
python pdf_sanitizer.py input.pdf --json
python pdf_sanitizer.py input.pdf --strict
python pdf_sanitizer.py --clean-artifacts --clean-dir .
```

常用参数：
- `--json`: 输出机器可读 JSON
- `--out <path>`: 写入 JSON 报告文件
- `--extract <dir>`: 导出可疑对象原始数据
- `--strict`: 更激进阈值
- `--verbose`: 输出更多证据
- `--clean-artifacts`: 清理生成产物并退出

退出码：
- `0`: 无高危触发项
- `1`: 存在高危触发项
- `2`: 处理失败

### CLI: LLM 指令扫描

```bash
python -m pdf_check.cli /path/to/file.pdf --json
python -m pdf_check.cli /path/to/file.pdf --llm-strict
python -m pdf_check.cli /path/to/file.pdf --llm-keywords custom_rules.yaml --json
```

### Web UI

```bash
python -m pdf_check.web_app
```

访问：`http://127.0.0.1:5000`

功能：
- 上传 PDF 后进行静态扫描
- 展示风险摘要与明细
- 下载清洗结果：`Clean Markdown` / `Clean PDF`

<p align="right">(<a href="#readme-top">回到顶部</a>)</p>

## 威胁模型与边界

本项目只做静态分析，不会：
- 执行 JavaScript
- 自动打开外部链接
- 根据 PDF 内容执行系统命令

这使其适合用于预审、CI 集成、批量筛查场景。

## 路线图

- [x] PDF 结构与内容流检测
- [x] Web 上传检测页面
- [x] 清洗导出（Markdown / PDF）
- [x] GitHub Actions 自动化测试
- [ ] 更精细的可视化定位（页面热区叠加）
- [ ] 规则配置中心（可视化管理自定义规则）

参见 Issues：<https://github.com/fengxiaohu/pdf-check/issues>

<p align="right">(<a href="#readme-top">回到顶部</a>)</p>

## 贡献

欢迎贡献。推荐流程：
1. Fork 仓库
2. 创建分支：`git checkout -b feature/your-feature`
3. 提交代码：`git commit -m "feat: ..."`
4. 推送分支并发起 Pull Request

## 许可证

本项目采用 **MIT License**。详见 [`LICENSE`](LICENSE)。

## 联系方式

- GitHub: <https://github.com/fengxiaohu>
- 项目地址: <https://github.com/fengxiaohu/pdf-check>

## 致谢

- [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
- [pikepdf](https://github.com/pikepdf/pikepdf)
- [pypdf](https://github.com/py-pdf/pypdf)
- [Flask](https://flask.palletsprojects.com/)

<p align="right">(<a href="#readme-top">回到顶部</a>)</p>
