# Type Confusion 基本原理

所谓 Type Confusion，就是当数据在申请、初始化之后的类型以及在之后对他使用的时候的类型不同（比如指向了不同的类），这时可能会因为类型中的字段偏移位置的不同、对应的数据不同，从而导致错误的函数指针等数据在代码中的出现，某些情况可能会出现任意代码执行。

Type Confusion 通常出现在 JavaScript 等这些脚本解析引擎中。在这些解析引擎中，出于对字节码的优化（通常只针对调用频繁的代码进行优化），会被 JIT 编译器编译成为机器码。而在后续执行时，会检查机器码中的数据的类型是否一致，如果不一致则会做出一些处理（比如返回使用解释器执行字节码，或者重新生成机器码）。而如果在生成了机器码之后，对目标对象的类型进行改变，并且使得这种类型的变化是不会被检测到的，那么在执行机器码的时候就会使得执行出错，从而发生 Type Confusion 错误。

改变数据类型的方式通常有两种（以数组为例）：

1. 通过没有检测的回调对数组类型进行修改；
2. 通过合理的函数对数组类型进行修改；

比较常见的攻击形式是：

1. 创建一个 NativeIntArray
2. 重复多次向 NativeIntArray 插入数据的操作，使得 JIT 编译器对其进行编译优化
3. 在插入过程中使用方法改变数组的类型，而 JIT 没有检测到这种类型变化
4. 通过类型的改变，从而对其进行利用（比如 NativeIntArray 转成 VarArray 之后，可以对 VarArray 中存储的指针进行类似 Int 值的更新，从而构造 DataView，获得任意内存读写的能力）

例子：<http://blogs.360.cn/post/When-GC-Triggers-Callback.html>

本例的弹出计算器的讲解中，借助 VBScript 的对象在 JavaScript 中被释放后会延迟调用析构函数的特点，将 NativeIntArray 转变成为 VarArray，这时通过 VarArray 控制一块可控的内存区域（实际上是数组的真实数据存储区域），从而可以伪造 DataView。之后通过伪造的 DataView，对任意内存进行读写，获得调用 calc 的命令，对数组的虚函数区域进行写入，然后调用对应的函数即可。

例子：<http://www.phrack.org/papers/jit_exploitation.html>

本例通过 this.Object.create 方法会将 propertyArray 转成 NameDictionary 存储的方式且不会额外增加 JIT 引擎检查的漏洞，通过构造两个不同属性，一个是 Double 类型，一个是 Object 类型，从而来实现内存的泄漏，并通过构建两个 ArrayBuffer 类型，修改一个 ArrayBuffer 的 backingStore 指针指向另一个 ArrayBuffer，从而实现任意内存的读写。
