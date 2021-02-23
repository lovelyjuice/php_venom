通过随机异或和加密payload动态免杀所有php文件。仅支持纯php文件，不支持在php文件中嵌入HTML文档，仅适用于php7.1以下版本，php7.1及以上版本由于assert函数无法动态执行代码，因此该脚本生成的免杀webshell无法正常运行。

原理参考：[利用随机异或无限免杀D盾蚁剑版](https://github.com/AntSword-Store/as_webshell_venom)

## 注意：需要bypass的php文件中必须包含开始标签 `<?php`