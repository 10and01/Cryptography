# DES Web 浏览器可视化

本项目仅保留一种可视化方式：
- Web 浏览器滚动演示（PPT 风格）

## 功能

- DES 加密全过程：逐块、逐轮展示
- DES 解密全过程：逐块、逐轮展示
- 每页内置 DES 阶段模块框架图，并对当前阶段高亮
- 轮函数关键中间值展示：
  - 子密钥
  - E 扩展输出
  - XOR 输出
  - S 盒输出
  - P 盒输出
  - L/R 更新结果

## 文件结构

- Des.py：DES 算法实现
- web_visualization.py：唯一可视化入口
- des_visualization_slides.html：运行后自动生成的页面

## 运行

```bash
python web_visualization.py
```

运行后会提示输入密钥和明文，并自动打开浏览器页面。

## 页面交互

- 鼠标滚轮：上下翻页
- ArrowDown / PageDown / Space：下一页
- ArrowUp / PageUp：上一页

## 阶段模块框架图

每一页顶部显示 DES 主流程模块：

- 输入/填充
- 初始置换 IP
- 子密钥生成 PC1/PC2
- 扩展置换 E
- 与子密钥 XOR
- S 盒替换
- P 盒置换
- Feistel 更新
- 交换 + PI
- 输出

当前页面对应阶段会高亮，便于把“当前数据变化”与“当前算法模块”对应起来。

## 说明

- 用途：密码学教学和演示
- 注意：DES 不建议用于现代生产安全场景
