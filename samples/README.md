# 校准样本目录

把已知标签的邮件放到对应子目录后，运行：

```bash
python calibrate.py            # 默认扫 ./samples
python calibrate.py --dir samples --ext eml,msg
```

## 目录约定（子目录名即标签，大小写不敏感）

| 钓鱼（阳性）可用的目录名 | 正常（阴性）可用的目录名 |
|---|---|
| phishing / malicious / bad / scam / spam / malware | benign / ham / legit / ok / safe / clean / normal / good |

例：

```
samples/
  phishing/        ← 放已知钓鱼邮件（.msg/.eml）
    a.eml
  benign/          ← 放确认正常的邮件
    b.eml
```

## 脚本会做什么

1. 跑全套 analyzer（解析 + URL + 附件 + 内容 + 评分），输出每封得分与系统判定
2. 给出当前 `config.py` 阈值下的混淆矩阵 + 准确率/召回率/F1
3. 网格扫描 SAFE/SUSPICIOUS 两个阈值，输出每组指标的表，标出 F1 最高（召回优先）的最优切点
4. 把最优切点的两个值回填到 `config.py` 的 `SCORE_SAFE_MAX` / `SCORE_SUSPICIOUS_MAX` 即可

## 注意

- 会真实调用 LLM 与 VirusTotal（VT 限速 4 次/分钟），样本多时较慢
- 首次校准各放 10~20 封即可看出趋势
- 想调各维度权重/放大系数，改 `config.py` 的 `WEIGHT_*` 与 `DIM_AMP_*` 后重新跑