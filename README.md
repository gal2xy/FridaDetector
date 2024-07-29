# FridaDetector
native层实现 frida 检测，检测特征如下：

- 默认端口检测

  检测 frida-server 默认端口 27042 是否开放。

- 进程名检测

  遍历进程列表(/proc目录下)，检测进程名是否包含 “frida-server” 。

- D-Bus 协议通信检测

  frida 使用 D-Bus 协议通信，这个通信协议在Android系统中并不常见。遍历端口发送 D-Bus 认证消息，哪个端口回复了 REJECT，哪个端口上就运行了 frida-server。

- 扫描 maps 文件

  被 frida 附加的进程，在 proc/self/maps 文件中会多出如下文件名：frida-agent-64.so或frida-agent-32.so。

- 扫描 task 目录

  如果 frida 附加到了当前进程，那么在 /proc/self/task 目录下，就会存在运行 gmain、gdbus、gum-js-loop、pool-frida等的线程。

- 内存搜索

  在内存中扫描 frida 库特征，例如字符串 “LIBFRIDA”、“rpc”等。
