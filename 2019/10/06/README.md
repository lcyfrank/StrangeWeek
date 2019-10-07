# 2019.10.06

本周是国庆假期，每天的时间都由自己安排，比较轻松，也没有课堂上的学习内容。

## 课后内容

本周首先完成了组里的任务，包括之前与师兄交流提到的三元组，同时还有组里的工程项目。

然后是完成了课程作业，其中包括**体系结构**的一章内容（主要是静态流水线的相关内容），通过作业也加深了课堂上没有理解的从最初的两级流水线到最后的五级流水线的升级（我的理解是将指令执行部分划分地更细了，使得一拍时钟变短，导致主频提升），同时对前递技术加深了理解（要注意前递技术本质就是加了旁路，使得数据可以直接流通过去）。然后是对于**算法作业**的解决，解决的几道问题都比较简单：[从旋转数组中寻找最小值](https://leetcode.com/problems/find-minimum-in-rotated-sorted-array)（O(log n)）、[二叉树最远节点之间的距离](https://www.geeksforgeeks.org/diameter-of-a-binary-tree/)（O(n)）和完全二叉树的局部最小值的寻找（O(log n)）。此外，由于算法作业提到了可以使用 LaTeX，考虑到以后都要对其进行学习，而且之前帮师兄改论文的时候感受到了 LaTeX 的强大，因此这周还花了一点时间学习 LaTeX。*但是 LaTeX 实在太强大，要想全部涉猎还是太多了，因此只学了部分中文排版相关的内容，足以交作业。*

之后，继续学习 Fuzzing 的基本概念。本周学习的是网络协议 Fuzzing 的相关内容。对于网络协议，书中的讲解就是通过已知的协议格式，来生成符合协议标准的测试用例，对目标进行 Fuzzing。在错误检测方面，需要使用调试器与目标进行绑定，当目标崩溃时来显示目标的错误（同时还要根据相应来定位到引起出错的测试用例），在例子讲解中，书中使用了 SPIKE 在 Unix 系统下的 Fuzzing 事例，SPIKE 使用起来非常简单，当然功能也很简单（不过有可能是这本书较老，因此当时的 Fuzzing 技术跟现在已经不同了）。在 Windows 系统中，作者通过捕获一个已知的网络包，然后在需要变换的数据字段上打上标签，来对测试用例进行变换，从而实现对目标的 Fuzzing。

接着，看了一篇 Fuzzing 相关的论文：[Hawkeye: Towards a Desired Directed Grey-box Fuzzer](https://dl.acm.org/citation.cfm?id=3243849)。这篇论文主要是针对指导性的灰盒测试的 Fuzzing 的优化（所谓指导性 Fuzzing，就是给定了存在漏洞的地方或者可能存在漏洞的地方，再使用 Fuzzing 工具进行 Fuzzing）。作者通过提出四个基本属性：

1. 计算当前种子的执行轨迹与目标执行轨迹的距离的算法需要更加精准（不仅考虑函数之间是否会调用，还考虑函数调用的次数，同时加上执行轨迹的相似度，而不是单纯考虑运行到目标的距离）
2. 对于静态分析生成的结果需要准确，同时还要保证性能（作者特别强调了提取间接函数调用，即通过函数指针的调用）
3. 如何确定选择种子的策略，使得好的种子可以更优先被选取（作者用到了三级队列，首先根据之前的计算对种子进行评分，然后根据评分将种子分到三级队列中）
4. 如何确定更合理的种子变换方法（根据是否能执行到目标来调整变换策略）

对于以上四点，作者分别提出了相对较合理的修改意见和调整方式。

*看完这篇论文之后，感觉现在 Fuzzing 研究方向都在基于 AFL 这种灰盒 Fuzzing 的方式进行修改，并在执行过程中或者说执行之前提取足够多的信息对 Fuzzing 过程进行知道，而看的那本书的内容由于出版时间过早，还只是在讲解不同情况下的 Fuzzing 过程处理情况（种子的生成、错误的检测等），相比于现在的技术还是太不智能了。*

之后是看了 Web 的一章，这章主要讲解了对于访问控制的攻击。*不过总感觉介绍的访问控制的攻击与之前提到的遍历目标站点的全部隐藏内容有很大的重复，都是通过遍历、探索等手段，来验证目标站点存在的访问控制的漏洞。*访问控制的漏洞主要分为：管理相关功能 URL 暴露、基于 ID 的资源无限制访问、多步骤的功能的绕过（可以跳过前一阶段内容）、静态资源无限制访问、HTTP 不同方法之间的不限制访问、以及一些本来就不安全的访问控制。

最后，本周学了 [JavaScript 引擎的优化]((https://github.com/lcyfrank/Week/blob/master/2019/10/06/js_engine.md))的一些思想，大体了解了 JavaScript 中对象的存储形式、Inline Cache 的概念、对于方法的访问等。

## 总结

以上就是本周大体的学习内容。

本周由于课程作业较多，以及自己的一些事情，完成的计划内容较少。本周感觉自己的学习效率仍然较低，此外，对上周提到的前卫分析文章分析也比较少，需要对自己的时间规划做出一个调整。