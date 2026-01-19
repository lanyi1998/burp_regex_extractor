# Regex Extractor

Burp Suite 扩展，用于从 HTTP 请求/响应中快速提取正则表达式匹配内容。

## 功能特性

- **实时正则匹配**: 在响应数据上实时测试正则表达式
- **预设模板**: 内置常用正则模板（邮箱、手机号、IP地址、URL、身份证、MD5、Base64）
- **右键菜单**: 支持将选中的请求/响应发送到提取器
- **UTF-8 支持**: 完美支持中文等 UTF-8 编码内容

## 安装方法

1. 打开 Burp Suite
2. 进入 `Extender` -> `Extensions`
3. 点击 `Add` 按钮
4. 选择 `Python` 作为扩展类型
5. 选择 `regex_extractor.py` 文件
6. 点击 `Next` 完成加载

## 使用方法

### 方式一：右键发送

1. 在 Burp Suite 的任意位置（如 HTTP history、Proxy intercept）选中一个请求
2. 右键点击 -> `Send to Regex Extractor`
3. 在扩展面板中输入正则表达式进行匹配

### 方式二：手动粘贴

1. 切换到 `Regex Extractor` 标签页
2. 将响应数据粘贴到左侧文本框
3. 在右侧输入正则表达式，结果会实时显示

### 预设模板

点击 `Quick Select` 下拉框可快速选择预设的正则表达式：

- Email - 邮箱地址
- China Mobile Phone - 中国手机号
- IPv4 Address - IPv4 地址
- URL - URL
- ID Card (China) - 中国身份证号
- MD5 - MD5 哈希
- Base64 - Base64 编码

## 自定义预设

编辑 `regex_config.json` 文件添加自定义正则模板：

```json
{
    "Template Name": "your_regex_pattern_here"
}
```

## 环境要求

- Burp Suite Professional 或 Community Edition
- Jython（用于运行 Python 扩展）

## 文件说明

```
.
├── regex_extractor.py    # 扩展主程序
└── regex_config.json     # 正则预设配置文件
```
