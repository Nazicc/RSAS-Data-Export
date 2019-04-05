### 工具介绍
绿盟远程安全评估系统漏洞数据导出工具，只支持RSAS6.0以上版本。

写这个工具的时候刚开始接触Python，采用的是先读取HTML内容写入到临时文件，再用正则从临时文件匹配。

后来发现了xpath这个新大陆，本打算重新写一下，想了想，能用就行了。

工具涉及：读取目录下的文件、ZIP文件读取、正则表达式、Excel表格写入、文件读写、PyQt5、TKinter(舍弃)

### 功能

- [x] 自定义漏洞等级
- [x] 自定义导出数据
- [x] 自定义Excel模板
- [x] 支持导出的数据：主机名、IP地址、端口、协议、服务、漏洞名称、风险等级、整改建议、漏洞描述、漏洞CVE编号、扫描起始时间、扫描结束时间、漏洞扫描月份
- [x] 导出不同端口的同一个漏洞，也就是一个端口对应一个漏洞，保证导出漏洞的完整性。
- [x] 导出端口和导出网站为单独的功能，导出网站的功能是采用正则去匹配http、www这两个服务。

### 须知
- [x] 当一个漏洞存在两个或者两个以上CVE编号，则只取第一个CVE漏洞编号。
- [x] 当一个漏洞不存在CVE编号时，则替换为 漏洞暂无CVE编号 。
- [x] 当一个漏洞整改建议为空时（个别低危漏洞），导出留空。

### 下载
下载链接是Windows版本的，如果需要在其他平台使用，可下载源码自己打包。
链接: https://pan.baidu.com/s/1JyyNJGiK_ZEc7JUGm4Ap_Q 提取码: 5pxt

### 使用方法

导出的原始报告必须勾选主机报表才行，程序是直接读取zip的，不能解压，把原始报告放到一个文件夹内，路径选择对应的文件夹就可以了。

![](https://webing.io/do/images/rsas_1.8.gif)
