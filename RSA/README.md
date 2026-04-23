# RSA 加密解密与动态可视化

本项目包含两部分：

- `rsa_demo.py`: 使用 Python 实现 RSA 密钥生成、加密、解密流程。
- `index.html` + `app.js` + `style.css`: 动态网页可视化 RSA 过程。

默认明文为：`学号: 19230323; 姓名: 汪文韬`。

## 1. 运行 Python 版本

在项目目录下执行：

```bash
python rsa_demo.py
```

## 2. 打开网页可视化

直接双击 `index.html`，或在 VS Code 中打开该文件并使用 Live Server 预览。

## 3. 网页功能说明

- 自定义 `p`、`q`、`e` 并生成密钥。
- 输入明文并执行加密。
- 执行解密并验证恢复结果。
- 右侧时间线实时记录每一步操作。
