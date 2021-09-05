# Mojo

* <https://www.jianshu.com/p/ce068f112945>

Mojo 是一种消息传递的 IPC 机制，通过 mojom 文件定义 Mojo 接口，之后会生成接收方与请求方的接口。请求方请求相应的接口，接收方实现接口，然后如果接收方需要发送回数据给请求方，需要通过 `callback` 来实现。

一个消息管道（PIPE）是一对端点（endpoints），每一个端点都有一个消息传入队列，在一个端点上写一条消息可以有效地将该消息排队到另一个端点上，因此消息管道是双向的。Chromium 实现的 Mojo 机制，通过 `mojom` 文件描述接口。给定 mojom 接口和消息管道，可以将其中一个端点指定为 Remote，用于发送该接口描述的消息；另一个端点为 Receiver，用于接收该接口消息（但是记住 mojom 消息管道仍然是双向的，消息是需要回复的）。

为了接收到消息，Receiver 端点必须与 mojom 接口的实现相关联。

例如，下列是一个 mojom 文件定义的接口：

```mojom
// src/example/public/mojom/ping_responder.mojom
module example.mojom;


interface PingResponder {
  // Receives a "Ping" and responds with a random integer.
  Ping() => (int32 random);
};
```

接下来需要创建管道。在 Mojo 中，一般 Remote 端（即消息发送端）通常是管道的创建者，例如下列代码位于 Render 中：

```c++
// src/third_party/blink/example/public/ping_responder.h
mojo::Remote<example::mojom::PingResponder> ping_responder;
mojo::PendingReceiver<example::mojom::PingResponder> receiver =
    ping_responder.BindNewPipeAndPassReceiver();
```

其中，`ping_responder` 是 Remote 对象，receiver 是一个 Receiver。`BindNewPipeAndPassReceiver()` 是创建消息管道最常见的方式，最终可以返回一个 Receiver（这个 Receiver 实际上什么也做不了，只是消息管道端点的惰性保持器）。

创建管道之后，通过调用 Remote 的接口即可发送消息，例如：

```c++
// src/third_party/blink/example/public/ping_responder.h
ping_responder->Ping(base::BindOnce(&OnPong));
```

通过上述就可以将消息从 Render 发送到浏览器进程。但是需要**注意**的是，为了在 Render 中收到消息，必须在调用 OnPong 方法调用之前（即收到消息之前？）保持 ping_responder 对象存活（因为它是管道的一个端点）；

之后需要解决从浏览器进程获得消息的问题，首先需要吧之前得到的 PendingReceiver 对象发送给浏览器。获取 PendingReceiver 最常见的方式是将其作为方法参数传递到其他接口上（借助其他接口来发送？）。在浏览器中，Render 进程与浏览器进程始终有一个链接的接口是 BrowserInterfaceBroker，这个接口允许传递任意的 Receiver，因此，使用如下方式可以将 Receiver 从 Render 进程传递到浏览器进程：

```c++
RenderFrame* my_frame = GetMyFrame();
my_frame->GetBrowserInterfaceBroker().GetInterface(std::move(receiver));
```

最后是浏览器端获取消息。首先需要实现 PingResponder 接口：

```c++
#include "example/public/mojom/ping_responder.mojom.h"

class PingResponderImpl : example::mojom::PingResponder {
 public:
  explicit PingResponderImpl(mojo::PendingReceiver<example::mojom::PingResponder> receiver)
      : receiver_(this, std::move(receiver)) {}

  // example::mojom::PingResponder:
  void Ping(PingCallback callback) override {
    // Respond with a random 4, chosen by fair dice roll.
    std::move(callback).Run(4);
  }

 private:
  mojo::Receiver<example::mojom::PingResponder> receiver_;

  DISALLOW_COPY_AND_ASSIGN(PingResponderImpl);
};
```

而 RenderFrameHostImpl 拥有 BrowserInterfaceBroker 的实现，当这个实现（Impl）接收到 GetInterface 方法的调用时，会调用之前为此特定接口注册的处理程序，例如 GetPingResponder 方法：

```c++
// render_frame_host_impl.h
class RenderFrameHostImpl
  ...
  void GetPingResponder(mojo::PendingReceiver<example::mojom::PingResponder> receiver);
  ...
 private:
  ...
  std::unique_ptr<PingResponderImpl> ping_responder_;
  ...
};


// render_frame_host_impl.cc
void RenderFrameHostImpl::GetPingResponder(
    mojo::PendingReceiver<example::mojom::PingResponder> receiver) {
  ping_responder_ = std::make_unique<PingResponderImpl>(std::move(receiver));
}


// browser_interface_binders.cc
void PopulateFrameBinders(RenderFrameHostImpl* host,
                          mojo::BinderMap* map) {
...
  // Register the handler for PingResponder.
  map->Add<example::mojom::PingResponder>(base::BindRepeating(
    &RenderFrameHostImpl::GetPingResponder, base::Unretained(host)));
}
```