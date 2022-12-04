NX：-z execstack / -z noexecstack (关闭 / 开启)    不让执行栈上的数据，于是JMP ESP就不能用了
Canary：-fno-stack-protector /-fstack-protector / -fstack-protector-all (关闭 / 开启 / 全开启)  栈里插入cookie信息
ASLR和PIE：-no-pie / -pie (关闭 / 开启)   地址随机化，另外打开后会有get_pc_thunk

![1](.\1.png)

RELRO：-z norelro / -z lazy / -z now (关闭 / 部分开启 / 完全开启)  对GOT表具有写权限

