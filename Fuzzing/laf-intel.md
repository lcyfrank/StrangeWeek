# laf-intel

> 本文是对 **laf-intel** 技术的一些记录，原文来自：
>
> <https://lafintel.wordpress.com/2016/08/15/circumventing-fuzzing-roadblocks-with-compiler-transformations/>

## 基本思想

**laf-intel** 是基于 **AFL** 实现的一个小技术，其基本的思想是 AFL 在对目标程序进行模糊测试时，会通过相应的覆盖率信息指导模糊测试的突变，对于发现了新的路径的测试用例，AFL 会将该测试用例进行保存，而对于未发现新的路径的测试用例，AFL 会将其抛弃。

但是，如果 AFL 遇到如下情况时，这种策略显得有点无力：

```c
if (input == 0xabad1dea) {
    /* terribly buggy code */
} else {
    /* secure code */
}
```

在模糊测试的过程中，只有当 `input` 被突变成为 `0xabad1dea` 时，测试用例才会触发漏洞代码，而其他情况均会进入 `else` 分支。这就导致即使 `input` 的值被突变成了 `0xabad1dee` 时，在当前情况下的模糊测试过程中，其与 `0x0` 的效果是一样的。因此，无法指导突变器对测试用例进行更好地突变。

为了解决上述问题，**laf-intel** 使用一种很直白的方式，将上述的 `if` 语句进行拆分，由一个大的条件判断拆分成多个小的条件判断，如：

```c
if (input >> 24 == 0xab){
    if ((input & 0xff0000) >> 16 == 0xad) {
        if ((input & 0xff00) >> 8 == 0x1d) {
            if ((input & 0xff) == 0xea) {
                /* terribly buggy code */
                goto end;
            }
        }
    }
}
```

这样，如果 AFL 猜中了第一个字节的值，则该测试用例会被保存，使得下一次模糊测试的过程会在该测试用例的基础上进行，增加了目标值被命中的概率。

基于上述原理，作者实现了 3 个插件，分别是针对基本的比较进行拆分，针对 `strcmp`、`memcmp` 函数进行拆分以及针对 `switch` 语句进行拆分。

## 实现细节

在基本的比较拆分过程中，除了 `==` 运算符，还有 `<`、`>`、`!=`、`<=`、`>=` 等，作者将 `<=` 和 `>=` 两个运算符拆分成 `==` 和 `<` 与 `>` 两个部分，同时，对于有符号数值的比较，将其拆分成符号位的比较和无符号数的比较。之后将 `==`、`<`、`>` 和 `!=` 四个运算符的比较进行逐字节拆分。

对于比较函数的拆分，比如 `strcmp`，则对其进行逐字符拆分。例如，对于：

```c
if(!strcmp(directive, "crash")) {
    programbug()
}
```

将其拆分后得到：

```c
if(directive[0] == 'c')
    if(directive[1] == 'r')
        if(directive[2] == 'a')
            if(directive[3] == 's')
                if(directive[4] == 'h')
                    if(directive[5] == 0)
                        programbug()
```

但是这种只能当目标程序在编译时就知道所比较的字符串的值以及字符串的长度的情况下可以进行拆分，因此仍然具有一些局限性。

对于 `Switch` 语句，编译器拆分得到的结果通常不适合用做 AFL 的路径发现，因此作者对 `Switch` 语句进行了重写，这一个过程比较复杂，对于下面的语句：

```c
int x = userinput();
switch(x) {
    case 0x11ff:
        /* handle case 0x11ff */
        break;
    case 0x22ff:
        /* handle case 0x22ff */
        break;
    default:
        /* handle default */
}
```

将其重写得到如下语句：

```c
int x = userinput();
if(x >> 24 == 0) {
    if((x & 0xff0000) >> 16 == 0x00) {
        if((x & 0xff) == 0xff) {
            if((x & 0xff00) >> 8 == 0x11) {
                /* handle case 0x11ff */
                goto after_switch;
            } else if((x & 0xff00) >> 8 == 0x22) {
                /* handle case 0x22ff */
                goto after_switch;
            } else {
                goto default_case;
            }
        }
        goto default_case;
    }
    goto default_case;
}

default_case:
    /* handle default */

after_switch:
```

使用这种方式可以提高路径探索的能力。
