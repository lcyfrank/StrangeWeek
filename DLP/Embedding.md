# 嵌入

类似于自然语言处理，由于程序表示形式为文本的源代码或者汇编指令，因此为了更好地使用神经网络对程序进行处理，通常需要对程序进行预处理，将程序的源代码或者汇编指令嵌入到数字空间中，形成向量之后，再进一步进行后续的工作。因此在使用神经网络对程序进行分析、处理之前，需要对嵌入的思想和方式进行大致了解。

* [Distributed Representations of Sentences and Documents](#distributed-representations-of-sentences-and-documents)：借助 **Word2vector** 的思想对自然语言文本的段落生成向量表示

---

## Distributed Representations of Sentences and Documents

*International conference on machine learning. PMLR, 2014.*

作者提到，为了表示文本信息，对文本信息进行向量化表示，最简单的方法是使用 **bag-of-words** 的方式。但是这种方式存在如下几个缺点：

* 这种表示方式未考虑文本内部单词之间的语义相关性；
* 这种表示方式通常有很高的维度，较稀疏，导致效率不高；

因此，作者提出了一种称为 **Paragraph Vector** 的形式对文本信息进行表示，这种方式可以使用定长的向量，表示变长的文本内容，且向量中包含一定的文本语义信息。

作者分析到，之前用来表示变长文本内容的方式都是从词的表示向量中拓展而来，其中有对得到的词向量作加权平均来得到完整的文本内容的表示，但是这种方式忽略了词与词之间的顺序关系；另一种方式是通过类似解析树的方式对文本内容进行解析，得到单词顺序之后组合词向量，但是这种方式只能适用于句子。

而作者提出的 Paragraph Vector 可以使用向量的形式来表示任意类型的文本，包括句子、段落甚至整个文档，而且在表示这些内容的同时在向量中包含一定的语义信息。

作者提出的方法基于 **Word2vector** 的思想，借助环境词来预测当前词，也就是最大化下面公式：

<img src="./img/maximum.png" width=300px>

其中，具体的 `P` 可以通过 Softmax 来计算：

<img src="./img/softmax.png" width=300px>

式中的 `y` 可以定义为如下形式：

<img src="./img/softmax_y.png" width=300px>

其中 `h` 可以被定义为多个向量的拼接或者多个词向量求平均的操作。

作者认为，在训练 Paragraph Vector 的过程中，词向量由于可以捕获上下文关系，可以帮助提取语义信息，同时还能作为预测任务的间接结果。因此，在训练 Paragraph Vector 的过程中，用到了 Word Vector 的训练。

具体的，对于文本中的每一个段落，作者将其映射到唯一的一个向量中，同时，对于段落中的每一个词，也将其映射到另一个向量中，段落向量与词向量可以用拼接或者加权和的方式从而来预测上下文中的下一个词。单词的上下文可以看作是一个滑动窗口，在段落上滑动，从而得到不同的训练数据。在训练过程中，段落向量是每个段落唯一的，不会在段落之间共享，而段落内的词向量则在多个段落之间共享，即不同段落之间的相同词共享同一个词向量。最终训练完成后会分别得到每个段落的段落向量和每个词的词向量。

在预测阶段，对于每个新的段落，都需要采用与训练过程类似的步骤来训练新的段落向量，而保持其他参数不变。在训练得到段落向量之后，可以用这个向量进行更近一步的工作。

Paragraph Vector 的好处是可以在没有 `label` 的数据中表现良好，由于训练过程中具有语义信息，因此最终得到的段落向量拥有较好的语义特征。

最后作者使用几个数据集在情感分析和信息提取层面上，使用 Paragraph Vector 的方法提取出段落向量进行实验，均得到较好的结果。