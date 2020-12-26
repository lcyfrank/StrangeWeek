# AF_PACKET 套接字

**AF_PACKET** 套接字允许用户在设备驱动层面收发数据包，基于这一特点，使用 AF_PACKET 可以在物理层上实现新的数据传输协议，同时可以实现嗅探器，对一些高层的协议包进行嗅探。

为了使得内核可以创建 AF_PACKET，内核编译时需要开启 **CONFIG_PAKCET=y** 配置。同时使用 AF_PACKET 的进程必须具有 **CAP_NET_RAW** 的 **Capability**，或者内核在编译时开启 **CONFIG_USER_NS=y** 配置，允许非特权级用户名字空间，也可以直接使用 AF_PACKET。

AF_PACKET 类型的 `socket` 可以使用如下代码进行创建：

```c
fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```

其中 **ETH_P_ALL** 表示监听任何协议的数据包。调用上述函数之后会在内核创建得到一个 `packet_sock` 结构体实例，该实例主要字段如下所示：

```c
struct packet_sock {
    struct sock sk;
    // …
    struct packet_ring_buffer rx_ring;
    struct packet_ring_buffer tx_ring;
    // …
    enum tpacket_versions tp_version;
    // …
    int (*xmit)(struct sk_buffer *skb);
    // …
}
```

在创建了 AF_PACKET 之后，可以使用相应的 `send`/`recv` 系统调用对数据进行收发。在收发时，如果提供 **Ring Buffer**，可以提高收发数据时的效率，Ring Buffer 具有不同的版本（TPACKET_V1、TPACKET_V2、TPACKET_V3），同样可以使用 `setsockopt` 函数，通过指定 **PACKET_VERSION** 选项指定，上面的 `tp_version` 字段就是对应的 Ring Buffer 的版本，`rx_ring` 与 `tx_ring` 则对应两种不同类型的 Ring Buffer。

## Ring Buffer

Ring Buffer 是一种用来传输数据的结构，可以同时在内核态与用户态之间共享数据。数据包在 Ring Buffer 中存储在单独的 **Frame** 中，多个 Frame 被分组为一个 Block。对于 TPACKET_V3 来说，每个 Frame 的大小不需要固定。

<img src="./img/ring_buffer_block" width="600px">

每一个 Block 都有一个对应的 `header`，存储在 Block 的地址头部，使用结构体 `struct tpacket_block_desc` 表示：

```c
struct tpacket_hdr_v1 {
    __u32 block_status;
    __u32 num_pkts;
    __u32 offset_to_first_pkt;
    __u32 blk_len;
    // …
}

union tpacket_bd_header_u {
    struct tpacket_hdr_v1 bh1;
};

struct tpacket_block_desc {
    __u32 version;
    __u32 offset_to_priv;
    union tpacket_bd_header_u hdr;
};
```

其中 `block_status` 表示当前 Block 的状态，用来指示当前 Block 是被内核态（TP_STATUS_KERNEL）使用还是用户态（TP_STATUS_USER）使用。通常在内核态将数据存储到 Block 中，当 Block 满了之后，会将状态设置为 TP_STATUS_USER，然后用户态从中读取数据，完成之后将该状态重新设置为 TP_STATUS_KERNEL。

此外，每个 Frame 也有对应的 header 数据，使用 `struct tpacket3_hdr` 结构体表示：

```c
struct tpacket3_hdr {
    __u32 tp_next_offset;
    // …
};
```

由于 Frame 的大小是不固定的，因此需要一个字段来指向当前 Block 中的下一个 Frame，将它们串起来，因此 `tp_next_offset` 字段用来指向下一个 Frame 的偏移。当一个 Block 的数据满了之后，这个 Block 就会被释放到用户态空间，供用户态访问。

Ring Buffer 可以使用 `setsockopt` 函数，通过 PACKET_TX_RING 或 PACKET_RX_RING 选项进行创建，例如如下代码可以指定并创建 TPACKET_V3 版本的 PACKET_RX_RING 类型的 Ring Buffer：

```c
int v = TPACKET_V3;
setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
```

其中，传递的 `req` 参数为一个 `struct tpacket_req3` 类型的结构体：

```c
struct tpacket_req3 {
    unsigned int    tp_block_size;  /* Minimal size of contiguous block */
    unsigned int    tp_block_nr;    /* Number of blocks */
    unsigned int    tp_frame_size;  /* Size of frame */
    unsigned int    tp_frame_nr;    /* Total number of frames */
    unsigned int    tp_retire_blk_tov; /* timeout in msecs */
    unsigned int    tp_sizeof_priv; /* offset to private data area */
    unsigned int    tp_feature_req_word;
};
```

上述 `tp_block_size` 和 `tp_block_nr` 表示 Block 的大小和 Block 的数量，同理 `tp_frame_size` 和 `tp_frame_nr` 也表示 Frame 的大小和数量，但是 TPACKET_V3 中由于每个大小不需要固定，因此这两个字段会被忽视。`tp_sizeof_priv` 表示在 Block 中存放的私有的数据，该数据可以以任何形式组织，且内核态不会访问该数据。之前提到，当 Block 在内核态中满了之后，该 Block 会被释放到用户态。但是有时候用户态需要尽早得到数据包的信息，因此这里使用 `tp_retire_blk_tov` 字段，指定 Block 被释放到用户态的时间间隔。

Ring Buffer 在内核中由 `struct packet_ring_buffer` 表示，该结构体如下：

```c
struct packet_ring_buffer {
    struct pgv *pg_vec;
    // …
    struct tpacket_kbdq_core prb_bdqc;
};
```

其中 `pg_vec` 字段为存储多个 Block 指针的数组，如下图所示，因此 Block 之间是可以不连续的。

<img src="./img/pg_vec_inner" width="600px">

`prb_bdqc` 字段的类型如下：

```c
struct tpacket_kbdq_core {
    // …
    unsigned short blk_sizeof_priv;
    // …
    char *nxt_offset;
    // …
    struct timer_list retire_blk_timer;
};
```

其中 `blk_sizeof_priv` 字段表示当前 Ring Buffer 中每个 Block 的 Private Data 的大小，`nxt_offset` 指示接下来的数据包存放在哪个 Block 中。
