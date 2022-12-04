- copy_to_user函数

```c
#include <linux/uaccess.h>
unsigned long copy_to_user(void __user *to, const void *from, unsigned long n);
```

如果数据拷贝成功，则返回零；否则，返回没有拷贝成功的数据字节数。

*to是用户空间的指针，

*from是内核空间指针，

n表示从内核空间向用户空间拷贝数据的字节数

- copy_from_user

```c
unsigned long copy_from_user(void * to, const void __user * from, unsigned long n)
```

第一个参数to是内核空间的数据目标地址指针，

第二个参数from是用户空间的数据源地址指针，

第三个参数n是数据的长度。

如果数据拷贝成功，则返回零；否则，返回没有拷贝成功的数据字节数。