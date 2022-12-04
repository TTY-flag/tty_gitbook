### fmt（格式化字符串漏洞）



#### **格式化字符串函数介绍**

格式化字符串函数可以接受可变数量的参数，并将第一个参数作为格式化字符串，根据其来解析之后的参数。通俗来说，格式化字符串函数就是将计算机内存中表示的数据转化为我们人类可读的字符串格式。几乎所有的 C/C++ 程序都会利用格式化字符串函数来输出信息，调试程序，或者处理字符串。



常见的有格式化字符串函数有

- 输入
  - scanf
- 输出

| 函数                      | 基本介绍                               |
| ------------------------- | -------------------------------------- |
| printf                    | 输出到 stdout                          |
| fprintf                   | 输出到指定 FILE 流                     |
| vprintf                   | 根据参数列表格式化输出到 stdout        |
| vfprintf                  | 根据参数列表格式化输出到指定 FILE 流   |
| sprintf                   | 输出到字符串                           |
| snprintf                  | 输出指定字节数到字符串                 |
| vsprintf                  | 根据参数列表格式化输出到字符串         |
| vsnprintf                 | 根据参数列表格式化输出指定字节到字符串 |
| setproctitle              | 设置 argv                              |
| syslog                    | 输出日志                               |
| err, verr, warn, vwarn 等 | 。。。                                 |

### 格式化字符串 

这里我们了解一下格式化字符串的格式，其基本格式如下



```
%[parameter][flags][field width][.precision][length]type
```

每一种 pattern 的含义请具体参考维基百科的[格式化字符串](https://zh.wikipedia.org/wiki/格式化字符串) 。以下几个 pattern 中的对应选择需要重点关注

- parameter
  - n$，获取格式化字符串中的指定参数
- flag
- field width
  - 输出的最小宽度
- precision
  - 输出的最大长度
- length，输出的长度
  - hh，输出一个字节
  - h，输出一个双字节
- type
  - d/i，有符号整数
  - u，无符号整数
  - x/X，16 进制 unsigned int 。x 使用小写字母；X 使用大写字母。如果指定了精度，则输出的数字不足时在左侧补 0。默认精度为 1。精度为 0 且值为 0，则输出为空。
  - o，8 进制 unsigned int 。如果指定了精度，则输出的数字不足时在左侧补 0。默认精度为 1。精度为 0 且值为 0，则输出为空。
  - s，如果没有用 l 标志，输出 null 结尾字符串直到精度规定的上限；如果没有指定精度，则输出所有字节。如果用了 l 标志，则对应函数参数指向 wchar_t 型的数组，输出时把每个宽字符转化为多字节字符，相当于调用 wcrtomb 函数。
  - c，如果没有用 l 标志，把 int 参数转为 unsigned char 型输出；如果用了 l 标志，把 wint_t 参数转为包含两个元素的 wchart_t 数组，其中第一个元素包含要输出的字符，第二个元素为 null 宽字符。
  - p， void * 型，输出对应变量的值。printf("%p",a) 用地址的格式打印变量 a 的值，printf("%p", &a) 打印变量 a 所在的地址。
  - n，不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
  - %， '`%`'字面值，不接受任何 flags, width。



**正常使用时的演示程序**

32位演示

源文件test1.c

```c
#include<stdio.h>
int main(){
	char *temp = "hello!this is a simple test!";
	printf("num1:%d\nnum2:%d\nnum3:%d\nnum4:%d\nnum5:%d\nnum6:%d\nnum7:%d\nstring in temp:%s",1,2,3,4,5,6,7,temp);
	return 0;
}
```

编译

```shell
gcc -g test1.c -o test1 -no-pie -m32
```

执行到printf时栈上的情况

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201126101442591.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1NTk1NzMy,size_16,color_FFFFFF,t_70#pic_center)



64位演示

源文件同上

编译

```shell
gcc -g test1.c -o test1 -no-pie
```

执行到printf时栈上和寄存器的情况

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201126101535729.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1NTk1NzMy,size_16,color_FFFFFF,t_70#pic_center)



**hhn和hn**

```c
#include<stdio.h>
int main(){  
	int a = 0x12345678;
	printf("%d,%hd,%hhd \n",a,a,a);
	return 0;
}
```

运行结果

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201126101555603.png#pic_center)



**fmt例1（内存泄露）**

test2.c

```c
#include<stdio.h>
int main(){
	printf("%x-%x-%x-%x");
	return 0;
}
```

编译

```shell
gcc -g test2.c -o test2 -no-pie
```

运行结果

![在这里插入图片描述](https://img-blog.csdnimg.cn/2020112610162599.png#pic_center)



**fmt例2（指定参数泄露）**

```c
#include<stdio.h>
int main(){
	int a=1,b=2,c=3,d=4,e=5;
	printf("%1$d---%3$d\n",a,b,c,d,e);
	return 0;
}
```

编译

```shell
gcc -g test2.c -o test2 -no-pie
```

运行结果

![在这里插入图片描述](https://img-blog.csdnimg.cn/20201126101652983.png#pic_center)



**fmt例3（内存修改）**

```c
#include<stdio.h>
int main(){
	int n = 1;
	printf("aaaa%n\n",&n);
	printf("n=%d\n",n);
	return 0;
}
```

编译

```shell
gcc -g test2.c -o test2 -no-pie
```

运行结果


![在这里插入图片描述](https://img-blog.csdnimg.cn/20201126102006340.png#pic_center)



fmt字符串漏洞的作用：泄露内存信息（栈上信息、程序pie偏移、cannary）、任意地址写入。



















