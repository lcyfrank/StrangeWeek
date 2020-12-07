# Linux 内核基础

## 内核启动

### 从编译内核开始

[To-Do]

### 文件系统

通常 `cpio` 文件是提供给内核启动的文件系统，并且使用 `gzip` 压缩格式进行压缩。可以通过以下命令进行解压：

```sh
$ mv rootfs.cpio rootfs.cpio.gz; gzip -d rootfs.cpio.gz
$ mkdir path; cd path; cpio -idmv < ../rootfs.cpio
```

（注意，有一些提供的文件系统不是 `gzip` 格式，直接是 `cpio` 格式，所以只执行第二句命令就行）

在 `path` 目录下使用以下命令对该文件系统进行重打包：

```sh
$ find . | cpio -o -H newc | gzip > ../rootfs.cpio
```

## 内核内存分配

* <http://brieflyx.me/2020/heap/linux-kernel-slab-101/>
* <https://evilpan.com/2020/03/21/linux-slab/>

***Q:** 用户进程的内核态地址空间是不是整个系统共享的，就是说这个地方的内存管理（申请和释放）是整个系统统一管理的？*

---

Linux 内核内存分配主要使用伙伴系统（**Buddy**）以及 **Slab 分配器**共同实现（感觉类似用户态的 `mmap` 和 `malloc` 的关系）。对于 Buddy 来说，其基本思想是大块内存按照一定策略不断拆分（在到达最小块之前），而 Linux 中的 Buddy 的最小块就是「页」，页是内存分配的最基本的单位。Buddy 中的块的大小由 `order`（阶）指定。如果当前系统「页」的大小为 4K，那么 order 为 1 就是 `2^1 * 4K`，order 为 2 中的块就是 `2^2 * 4K`…

在 Buddy 中分配内存时，根据指定大小寻找对应的 order 的页，如果没有该页，则将高 order 的页进行分裂；释放时，如果这个块（页）是之前分裂得来的，则与其伙伴（即之前拆分的另一个块）重新合并。

基本上 Buddy 的思想就是上面这样，可以通过查看 `/proc/buddyinfo` 文件或者 `/proc/pagetypeinfo` 文件来查看系统 Buddy 块的信息，其中 Node 表示每一组 CPU 和本地内存；每一个 Node 下面可能会有多个内存设备（Zone），每一个 Zone 后面跟着的数字表示当前系统中连续 2^n 个页面的内存的数量（n 表示后面的第 n 个数字），如下图所示：

<img width="600px" src="./img/buddy">

而 Slab 分配器主要负责分配小的内存（其实就是将 Buddy 实现分配的内存通过 Slub 进行管理）。对于 Slab 分配器来说，**Object** 是最小的分配单元。Slab 分配器中，比较重要的数据结构是 `kmem_cache` 数据结构（该数据结构对应用户态的 `arena`）对内存进行管理。`kmem_cache` 中有着大量的 Slab，每个 Slab 由多个 **Page** 组成，每个 Page 里面则包含多个 Object。对于同一个 `kmem_cache` 数据来说，其中包含的每个 Object 的大小是一样的。关系图如下所示：

<img width="500px" src="./img/slab">

Linux 系统在启动之后，会有多个 `kmem_cache`，分别负责不同大小的 Object 进行分配，可以使用 `slabtop` 来进行查看：

<img width="600px" src="./img/slabtop">

通过使用以下 API 对内核堆内存进行操作：

* `kmem_cache_create`：指定 Object 的大小，创建一个 `kmem_cache`
* `kmem_cache_alloc`：在指定的 `kmem_cache` 中申请 Object，不需要指定大小
* `kmem_cache_free`：释放该 Object
* `kmalloc`：指定大小，申请内存，系统会在合适大小的 `kmem_cache` 中申请，如果太大了的话，还是直接调用 Buddy 进行申请
* `kfree`：对应 `kmalloc` 的释放

# 虚拟文件系统

* <https://zhuanlan.zhihu.com/p/69289429>
* <https://www.jianshu.com/p/8966d121263b>
* <https://github.com/psankar/simplefs>

文件系统就是指定对一块磁盘映像，用什么形式去解析（挂载），使其可以与 Linux 系统文件树连在一起。

Linux 内核使用虚拟文件系统（VFS）对具体的文件系统的操作进行抽象。使用虚拟文件系统，可以直接使用 `open()`、`read()`、`write()` 这样的系统调用对文件进行操作，而无需考虑具体的文件系统和实际的存储介质。

比如，在 Linux 中写一个文件，使用 `write()` 函数，它首先会调用 `sys_write()` 函数来进行处理，然后，`sys_write()` 会根据 `fd` 找到其对应的文件系统，同时找到文件系统中定义的 `write()` 操作，比如 `op_write()`，最后调用 `op_write()` 执行实际的操作（实际的操作由该虚拟文件系统决定）。所有需要被 Linux 所支持的文件系统类型，都需要定义一个对应的 VFS 接口，并定义一个 `file_system_type`，并在内核启动时注册到内核中，从而可以在 `mount` 一个文件系统时找到对应的操作：

```c
register_filesystem(...)
```

Linux 为了实现这种虚拟文件系统，抽象了 4 个对象：

* 超级块（`super_block`）：用来描述一个文件系统
    * 超级块中存储着一些文件系统的元信息，元信息中包含着索引节点的信息、挂载的标志、操作方法 `s_op`、安装权限、文件系统的大小区块等。`super_block` 中的 `s_op` 是文件系统中对超级块本身进行操作的方法。挂载文件系统时，就是在存储介质的特定位置写入 `super_block` 信息。`super_block` 在文件系统被加载之后，卸载之前会一直存在于内存中。
* 索引节点（`inode`）：用来表示文件系统中的文件
    * 包含 Linux 内核在操作文件时所需要的全部信息，包含目录相关信息、文件相关信息、引用计数等。只有当文件被访问时，才在内存中创建索引节点（*Q: 这个地方不太理解*）。
* 目录项（`dentry`）：路径的一部分，主要包含父目录项对象地址、子目录项链表、目录项操作指针
* 文件对象（`file`）：被进程所打开的文件

下面使用 `simplefs` 的代码来更好地理解 Linux 中的虚拟文件系统。在使用某一个虚拟文件系统之前，需要向内核注册该文件系统送的类型：

```c
struct file_system_type simplefs_fs_type = {
    .owner = THIS_MODULE,
    .name = "simplefs”,  /* 指定文件系统名称 */
    .mount = simplefs_mount,  /* 指定 mount 时的函数 */
    .kill_sb = simplefs_kill_superblock,
    .fs_flags = FS_REQUIRES_DEV,
};
```

之后，按照某个文件系统所定义的格式信息创建好磁盘映像文件（`img` 文件，可以看 `mkfs-simplefs.c` 代码），然后使用 `mount` 将其按照文件系统类型进行挂载时，会调用 `simplefs_mount` 函数，该函数会创建一个 `super_block` 对象，这个对象在当前映像被卸载之前都会存在于内存中。之后会调用 `simplefs_fill_super` 函数，在 `simplefs_fill_super` 函数中，会做一些校验，需要根据磁盘映像中的内容对当前的 `super_block` 对象进行初始化，包括 `s_op` 等。

```c
int simplefs_fill_super(struct super_block *sb, void *data, int silent) {

    /* ... */
    bh = sb_bread(sb, SIMPLEFS_SUPERBLOCK_BLOCK_NUMBER);  /* 读取磁盘中的信息 */
    sb_disk = (struct simplefs_super_block *)bh->b_data;

    /* 一些校验 */
    if (unlikely(sb_disk->magic != SIMPLEFS_MAGIC)) {
        printk(KERN_ERR
            "The filesystem that you try to mount is not of type simplefs. Magicnumber mismatch.");
        goto release;
    }

    if (unlikely(sb_disk->block_size != SIMPLEFS_DEFAULT_BLOCK_SIZE)) {
        printk(KERN_ERR
            "simplefs seem to be formatted using a non-standard block size.");
        goto release;
    }

    /* A magic number that uniquely identifies our filesystem type */
    /* 初始化 super_block */
    sb->s_magic = SIMPLEFS_MAGIC;
    sb->s_fs_info = sb_disk;
    sb->s_maxbytes = SIMPLEFS_DEFAULT_BLOCK_SIZE;
    sb->s_op = &simplefs_sops;

    /* ... */
}
```

同时，会根据磁盘映像中的内容设置根节点：

```c
/*...*/
root_inode = new_inode(sb);
root_inode->i_ino = SIMPLEFS_ROOTDIR_INODE_NUMBER;
inode_init_owner(root_inode, NULL, S_IFDIR);
root_inode->i_sb = sb;
root_inode->i_op = &simplefs_inode_ops;  /* 创建等操作 */
root_inode->i_fop = &simplefs_dir_operations;  /* 对文件读写的一些操作 */
root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime =
    current_time(root_inode);

root_inode->i_private =
    simplefs_get_inode(sb, SIMPLEFS_ROOTDIR_INODE_NUMBER);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
    sb->s_root = d_make_root(root_inode);
#else
    sb->s_root = d_alloc_root(root_inode);
#endif
/* … */
```

从而完成虚拟文件系统（映像）的挂载。

## 内核调试

[To-Do]

## 内核利用

内核利用的主要目的是获得权限提升，涉及到权限提升的有三个概念：

* `cred` 结构体：用于控制进程的权限，其中有 `uid`、`gid`、`suid`、`sgid` 等字段
* `prepare_kernel_cred` 函数：分配一个新的 `cred` 结构（凭证），通常使用 `prepare_kernel_cred(0)` 获得特权凭证
* `commit_creds` 函数：提交新的特权凭证

上述两个函数的地址可以通过 `/proc/kallsyms` 查看（有时候需要 `sudo`）。

### ret2usr

* <https://duasynt.com/slides/smep_bypass.pdf>
* <https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-1>
* <https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/linux-kernel-rop-ropping-your-way-to-part-2>

基本原理：用户态内存空间无法访问内核态内存空间，但是内核态内存空间可以访问用户态内存空间。因此通过修改内核态内存空间中的指针等数据指向用户态空间的代码，使得在 **Ring 0** 特权级的情况下执行用户态的代码，从而实现权限提升。如下图所示，修改内核态的 *Function ptr* 指向 `escalate_privs()` 或者 *Data struct ptr* 指向用户态的 *Data struct*，再指向 `escalate_privs()` 函数。通常 `escalate_privs()` 函数的内容如下：

```c
void escalate_privs() {
    commit_creds(prepare_kernel_cred(0));
}
```

<img width="600px" src="./img/ret2usr">

在完成了 `ret2usr`，调用了 `escalate_privs()` 函数之后，再执行 `system("/bin/sh")` 即可获得具有特权级的 Shell。

### SMEP 及其绕过

特权级执行保护（**SMEP**）是用来防止内核态内存直接访问用户态内存的代码进行执行，即内核态无法执行用户态代码。SMEP 是通过 CPU 来决定开启与关闭的，通常由 **CR4** 寄存器的第 **20** 位来控制，如果该位寄存器为 1，则表示开启 SMEP 保护。因此，要关闭 SMEP 保护可以直接使用 MOV 指令对 CR4 寄存器的值进行改写即可。可以使用 `cat /proc/cpuinfo | grep smep` 查看是否开启 SMEP。

那么如何绕过 SMEP 呢？最直白的方法是使用 **ROP** 关闭 SMEP。对于内核文件来说，有两种类型的格式：`vmlinux` 和 `vmlinuz`（`bzImage`/`zImage`，在发行版中位于 `/boot/vmlinuz-xxxxxx` 中）。`vmlinux` 是原始的二进制文件，可以从中提取 ROP 的 `gadgets`，而 `vmlinuz` 是经过压缩的格式。可以使用内核源码中提供的 `extract-vmlinux` 脚本从 `vmlinuz` 中提取出原始的 `vmlinux`。提取出 `vmlinux` 之后，就可以使用 **[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)** 等工具发现 ROP 的 `gadget`，进一步构造 ROP 链。

一般在用户态内存中构造 ROP 链，在构造 ROP 链之后，需要在内核态内存中完成 **Stack Pivot**，将内核栈转移到用户态内存空间，从而可以顺利执行 ROP 链，关闭 SMEP 保护，之后再执行与 `ret2usr` 相同的攻击流程即可。对于 Stack Pivot 的构造，与用户态内存利用相似，构造一些可以改变 RSP 指针的值的指令即可（如 `mov rsp XXX` 等）。

一般在用户态构造的 ROP 链的最终目的是改变 CR4 寄存器的值，因此基本的 ROP 布局如下：

<img width="600px" src="./img/rop_layout">

CR4 的原本的值（即 CR4_VALUE）通常可以使用 MOV 指令移到其他寄存器，方便构造 ROP 链的时候对值进行修改。此外，还有一些小技巧，比如当进行 Stack Pivot 的时候，如果 RAX 等寄存器的值是不可控的，因此无法可靠地控制转移栈的目标地址，此时可以将转移后的栈的地址看作一个随机值，然后在用户态空间大量申请内存，将 ROP 链进行堆喷，从而进行爆破。

除了构造 ROP 链对 SMEP 进行关闭之外，还可以直接使用 ROP 链调用 `commit_creds(prepare_kernel_cred(0));` 函数，从而完成特权提升。
