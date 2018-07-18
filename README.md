## 编译准备工作  
### 获得交叉编译工具链  
工具链相当于编译器。根据我的使用环境，从“https://archive.openwrt.org/chaos_calmer/15.05.1/ramips/mt7620/”下载了工具链“OpenWrt-SDK-15.05.1-ramips-mt7620_gcc-4.8-linaro_uClibc-0.9.33.2.Linux-x86_64.tar.bz2”。下载完成后解压。  
### 获得feeds  
feeds相当于依赖。因为本程序使用到了运行库，需要把用到的所有运行库一起编译。  
SQLite3：从https://github.com/openwrt/packages/tree/for-15.05/libs/sqlite3获取Makefile文件，放在工具链文件夹的package/feeds/packages/sqlite文件夹。  
libpcap：从https://git.archive.openwrt.org/15.05/openwrt.git?p=15.05/openwrt.git;a=commit;h=8b2aafcfc044bb73d19604d529f0b23b4415d7ef获取Makefile等所有文件，放在工具链文件夹的package/feeds/packages/libpcap文件夹。  
libpthread：工具链自带。  
### 准备编译  
使用非root用户在Linux终端打开工具链文件夹（如果使用root用户可能编译时会莫名其妙报错），执行命令make menuconfig。  
在Default Category分类下的NetworkTrafficMonitor、Libraries下的libpcap、及其database下的libsqlite3这三个选项前用M标记。保存配置并退出。  
## 编译  
执行make package/openwrt-NetworkTrafficMonitor/compile开始编译指定软件包，或make开始编译package里的所有包，带上参数V=s可以在编译时显示详细信息。  
## 测试  
如果一切正常，在SDK目录中的bin/ramips/packages/base/目录下会生成NetworkTrafficMonitor_0.0.1-1_ramips_24kec.ipk，在bin/ramips/packages/packages/目录下生成所需的依赖软件包。文件名会依目标平台的不同而略有不同。如果没有找到，那么一定是因为编译时出错了，要根据编译时屏幕显示的内容判断出错原因。  
通过SSH客户端与路由器建立连接管道，使用路由器上存在的唯一的用户root用户登录。通过scp（secure copy）或其它类似的功能把这些ipk文件复制到路由器。  
在终端内执行opkg install NetworkTrafficMonitor_0.0.1-1_ramips_24kec.ipk以安装，但在此之前需要先安装依赖，否则会因缺少依赖而安装失败。安装安装完成后，在终端内执行软件包名NetworkTrafficMonitor即可运行。卸载的话只要从路由器自带的软件包管理界面或通过执行命令opkg remove NetworkTrafficMonitor即可卸载。  
其中1~10每个选项的意义分别是：eth0是物理以太网卡，eth0.1，eth0.2是eth0上虚拟出来的逻辑接口（官方文档中叫vlan），分别对应物理lan口和物理wan口。br-lan口对应物理lan口和无线lan口。wlan1是无线桥接的无线广域网（wwan）口，wlan1-1是Wi-Fi接口。lo是本地回环（loopback）接口。any对应以上所有接口。usbmon是USB接口，尝试嗅探它们的网络流量会导致出错。

