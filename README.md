# webrtc 视频会话 demo

## 说在前面的话

本项目只用于学习和测试，其他用途概不负责。本项目对元项目的部分代码进行了 注释和修改，用于研究webrtc协议。
为什么要弄web-rtc呢，应为只需要php配合JavaScript就可以了，不需要配置服务器，而且传输性能比较好，延迟在1秒以内。
web-rtc是已经被封装好的，直接调用接口就行，其他的协议，比如rtmp，rtsp，flv,hls，PHP官方是不支持这些协议的，需要自己
使用tcp或者udp协议实现，可以使用workman，swoole，reactphp这些成熟的框架来实现，也可以自己用原生的PHP实现，不过感觉协议
太复杂了，心智负担太重了。
1. 依赖扩展

* ext-json
* ext-swoole (推荐使用最新 [release](https://github.com/swoole/swoole-src/releases/latest)
  版本或 [v4.4LTS](https://github.com/swoole/swoole-src/tree/v4.4.x) 版本)

2. 下载源码并启动

```shell
git clone git@github.com:2723659854/webrtc.git

php server.php
```


3. 本地访问：http://127.0.0.1:9504 <br>
4. 若需要局域网内访问，需要修改两个文件，一个是./config.php的ws地址配置，改成局域网地址，并且是wss协议 <br>
   否则浏览器无法通信，同时./server.php里面创建http服务的地方要开启ssl，取消ssl文件位置注释，否则浏览器 无法获取摄像头麦克风设备，无法获取媒体采集设备。 <br>
5. 局域网访问地址：https://192.168.4.120:9504 ，websocket地址：wss://192.168.4.120:9504 <br>
6. 如果是本地测试和局域网测试不需要打洞服务（内网穿透）。若部署到外网，可能需要打洞服务。 <br>
7. 部署swoole环境，可以使用hyperf的docker镜像文件，你也可以自己搭建。 <br>

```bash 
docker run --name hyperf -d --restart=always -v /e/swoole:/data/project  -p 9507:9507 -p 18306:18306  -p 9506:9506 -p 9504:9504  -it  --privileged -u root  --entrypoint /bin/sh  hyperf/hyperf:7.4-alpine-v3.11-swoole
```

7. 如果需要打洞服务，可以使用docker镜像。<br>
   文档地址：https://blog.csdn.net/Marclew_/article/details/129300377
   <br>
   turn项目地址：https://github.com/konoui/kurento-coturn-docker

```bash 
1. cd kurento-coturn-docker/coturn/
# 使用dockerfile,记住加点
2. sudo docker build --tag coturn .
# 后台运行coturn
3. sudo docker run -d -p 3478:3478 -p 3478:3478/udp coturn 

```

这里有一个问题，就是创建镜像的时候，复制脚本turnserver.sh到容器里面，但是会失败，会导致容器无法启动。
<br>
解决办法：就是先创建容器，然后进入容器后，手动创建这个脚本。当然dockerfile文件也需要改动，参考./Dockerfile文件。
<br>
可以在/boot目录下创建脚本，然后把原来项目的turnserver.sh内容复制粘贴进去，然后保存，修改脚本的可执行权限

```bash 
chmod +x ./turnserver.sh 
```

,最后执行脚本即可

```bash 
./turnserver.sh
```

<br>
修改turn的用户名，默认的用户名密码是：user=kurento:kurento

```bash 
docker exec -it <容器id> /bin/bash
 
vi etc/turnserver.conf
```

8. 测试结果 <br>
   如果使用手机测试，需要在应用设置里面，给浏览器添加麦克风和相机权限。<br>
   测试方法：<br>
   ----------------------------<br>
   电脑端：<br>
   QQ浏览器：本地正常，对端正常<br>
   谷歌浏览器：本地正常，对端正常<br>
   火狐浏览器：报错，不能使用<br>
   edge浏览器：本地正常，对端正常<br>
   =======================================================<br>
   qq浏览器：本地正常，对端正常<br>
   360浏览器：感觉只能播放本地和对端的其中一个，总有一个不能播放，估计是浏览器不能同时拉流和推流。<br>
   uc浏览器：直接显示没有权限，其实浏览器已经开启了权限，但是还是会报错<br>
   搜狗浏览器：本地正常，对端正常<br>
   夸克浏览器：似乎本地和对端不能正确建立连接<br>
   悟空浏览器：无法和对端建立连接，并且无法打开摄像头和麦克风<br>
   华为浏览器：本地正常，对端正常<br>
   百度浏览器：本地正常，对端正常<br>
   edge浏览器：本地正常，对端正常<br>
9. 项目运行流程
```text
1，首先是A客户端连接上ws之后，客户端创建本地媒体资源，A创建成功之后，发布客户端上线事件client-call
2，B客户端接收到上线事件client-call后，创建一个rtc客户端，绑定本地媒体资源，
然后广播自己的节点信息client-candidate。
3，A客户端收到client-candidate后，保存B的节点信息。
4，B客户端创建描述符信息，先自己保存，然后广播发送client-offer
5，A客户端收到client-offer，创建rtc客户端连接，绑定本地的媒体资源，
广播自己的节点client-candidate，
6，B客户端收到client-candidate信息后，保存A的节点信息。
7，A客户端保存B客户端的描述信息offer，然后创建并保存回答信息，就是描述符，
然后广播自己的描述符信息，client-answer
8，B客户端收到client-answer消息后，保存A客户端的answer消息，
9，连接建立完成，
```
10. 流程图
<img src="./webrtc.png" alt="流程图" >
11. 参考资料<br>
    webrtc服务的相关材料 <br>
    https://blog.csdn.net/qq_44476091/article/details/126505032  <br>
    https://blog.csdn.net/yinshipin007/article/details/124333112 <br>
    https://blog.csdn.net/ZYY6569XSW/article/details/130214048 <br>
12. 笔记<br>
    webrtc主要依赖的是JavaScript，基本上各大浏览器已经支持webrtc浏览器了。<br>
    运行原理：<br>PHP提供ws服务，当两个客户端通过ws服务获知对方地址并建立连接之后，客户端之间是点对点连接，不再依赖ws服务。客户端之间直接点对点传输媒体数据。 只要不刷新页面，两个客户端可以一直通信。
    <br>
    PHP主要负责提供http服务，ws服务，网关服务。JavaScript负责提供webrtc服务。<br>
    webrtc协议和rtmp，flv,hls协议不同之处是，webrtc是点对点传输数据，不需要服务器转发。<br>
13. 当然了，如果是多人场景，比如会议，多人直播，那是需要内网穿透的。 <br>
14. 关于直播 <br>
15. 推流：默认都是rtmp。一般使用obs客户端，FFmpeg客户端，也可以使用第三方推流软件，或者使用腾讯，华为等第三方的sdk自己开发推流软件。 <br>
16. 拉流：<br>
    rtmp协议：部分播放器是支持rtmp协议，可以直接播放。rtmp延迟一般是1秒-3秒，速度很快。但是似乎浏览器都不支持rtmp协议拉流。<br>
    hls协议：浏览器和播放器基本都支持拉流，但是hls是将媒体数据切片，然后传输，延迟很高。hls协议严格意义上说算不上实时直播，延迟至少是5秒，一般是15-35秒左右， 而且hls如果解码速度不够快的情况，
    延迟会累加，延迟最高可以达到1小时。如果用于直播pk场景，在线教学场景，游戏场景，会议场景，等对方收到消息，黄花菜都凉了。<br>
    flv协议：延迟基本稳定在在1-3秒，如果超过3秒，那可能就是你的服务器问题，或者推流问题。但是大多数浏览器认为flash不安全，所以需要使用flv.js播放。
    一般安卓的播放器也支持flv，苹果自带的播放器是不支持的，可以使用第三方的播放器，或者自己把flv.js嵌套进去，自己写个播放器。<br>
    web-rtc协议：这个主要就是为了浏览器设置的（如果某个浏览器不支持，那是浏览器厂商的问题，web-rtc属于标准协议，浏览器必须支持），也支持部分播放器，如果不支持就使用第三方SDK，比如腾讯，华为，阿里的sdk。web-rtc的速度是最快的，延迟在毫秒级别，
    如果延迟超过1秒，就要检查网络是否有问题，检查设备问题，检查浏览器或者播放器问题。速度快的原因是：web-rtc底层使用的是udp协议，而rtmp,hls,flv都是使用的tcp，udp没有那么复杂的握手环节，也不校验
    数据包是否完整，丢包也不会重发，所以速度就很快了。<br>
    rtsp协议：这个主要是用来做监控用的，比如摄像头监控。可以使用VLC插件播放，浏览器不能直接播放，需要将rtsp转码为flv或者mp4才可以播放。延迟一般是3秒。 <br>
17. 效果图见项目根目录的computer1.png和phone1.jpg两张截图。 <br>

