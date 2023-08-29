<?php include __DIR__ . '/../config.php' ?>
<!DOCTYPE html>
<html>
<head>

    <meta charset="utf-8">
    <meta name="description" content="webrt示例,一对一视频聊天-基于swoole实现">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1, maximum-scale=1">
    <meta itemprop="description" content="swoole webrtc 视频聊天 demo">
    <meta itemprop="name" content="AppRTC">
    <meta name="mobile-web-app-capable" content="yes">
    <meta id="theme-color" name="theme-color" content="#1e1e1e">
    <title>webrt示例,一对一视频聊天-基于swoole实现</title>
    <link rel="stylesheet" href="assets/css/bootstrap.min.css">
    <style>
        body {
            background-color: #fff;
            color: #333;
            font-family: 'Roboto', 'Open Sans', 'Lucida Grande', sans-serif;
            height: 100%;
            margin: 0;
            padding: 0;
            width: 100%;
        }

        .videos {
            font-size: 0;
            height: 100%;
            pointer-events: none;
            position: absolute;
            transition: all 1s;
            width: 100%;
        }

        #localVideo {
            height: 100%;
            max-height: 100%;
            max-width: 100%;
            object-fit: cover;
            /** 这里是设置镜像翻转画面 */
            /*-moz-transform: scale(-1, 1);*/
            /*-ms-transform: scale(-1, 1);*/
            /*-o-transform: scale(-1, 1);*/
            /*-webkit-transform: scale(-1, 1);*/
            /*transform: scale(-1, 1);*/
            /* 如果页面发生翻转则1秒的动画效果 */
            transition: opacity 1s;
            width: 100%;
        }

        #remoteVideo {
            display: block;
            height: 100%;
            max-height: 100%;
            max-width: 100%;
            object-fit: cover;
            position: absolute;
            /** 这里是设置镜像翻转画面 */
            /*-moz-transform: rotateY(180deg);*/
            /*-ms-transform: rotateY(180deg);*/
            /*-o-transform: rotateY(180deg);*/
            /*-webkit-transform: rotateY(180deg);*/
            /*transform: rotateY(180deg);*/
            /* 如果页面发生翻转则1秒的动画效果 */
            transition: opacity 1s;
            width: 100%;
        }
    </style>
</head>

<body>

<div class="videos">
    <video id="localVideo" autoplay style="width:800px;height:400px;margin: 10px" controls></video>
    <br>

    <video id="remoteVideo" autoplay style="width:800px;height:400px;margin: 10px" controls></video>
    <!--    class="hidden"-->
</div>

<script src="assets/js/jquery-3.2.1.min.js"></script>
<script src="assets/js/bootstrap.js"></script>
<script src="assets/js/adapter.js"></script>

<script type="text/javascript">
    /** ws 连接地址 */
    var WS_ADDRESS = '<?php echo $SIGNALING_ADDRESS;?>';
    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
    if (isMobile) {
        console.log('当前在手机端');
    } else {
        console.log('当前在PC端');
    }
    // 房间id
    var cid = getUrlParam('cid');
    /** 如果没有房间号 ，则随机生成房间号 */
    if (cid == '' || cid == null) {
        cid = Math.random().toString(36).substr(2);
        location.href = '?cid=' + cid;
    }
    /** 应答 */
    var answer = 0;

    // 基于订阅，把房间id作为主题
    /** 相当于注册事件，订阅事件 */
    var subject = 'private-video-room-' + cid;

    /** 建立与websocket的连接 */
    var ws = new WebSocket(WS_ADDRESS);
    // console.log(ws);
    ws.onopen = function () {
        console.log('ws连接成功');
        /** 订阅信道 ，订阅通道 */
        subscribe(subject);
        /** 获取正在使用的媒体设备，这里会弹出对话框让用户选择需要分享的窗口，可以选择浏览器的某一个标签，可以使命令行窗口，可以使打开的文档，编辑器,整个桌面等等 */
        //navigator.mediaDevices.getDisplayMedia({ 正在使用的媒体设备
        //navigator.mediaDevices.getUserMedia({ 摄像头
        if (isMobile) {
            /** 手机端 */
            navigator.mediaDevices.getUserMedia({
                /** 获取音频 */
                audio: true,
                /** 获取视频 */
                video: true
                /** 某些浏览器切换摄像头不起作用 */
                /*video:{
                    /!** user 前置 environment 后置 *!/
                    facingMode: 'environment'
                },*/

            }).then(function (stream) {
                /** 获取用户的媒体成功后，将媒体赋值给本地视频框 */
                localVideo.srcObject = stream;
                /** 设置音量:无效 */
                //localVideo.volume = 0.8;
                /** 自动播放:无效 */
                //localVideo.play()
                /** 保存本地媒体数据流 */
                localStream = stream;
                /** 给本地媒体窗口绑定loadedmetadata事件，就是媒体数据加载完成后触发 */
                localVideo.addEventListener('loadedmetadata', function () {
                    /** 发布事件客户端连接 client-call */
                    publish('client-call', null)
                });

            }).catch(function (e) {
                alert(e);
            });
        } else {
            navigator.mediaDevices.getDisplayMedia({
                /** 获取音频 */
                audio: true,
                /** 获取视频 */
                video: true
            }).then(function (stream) {
                /** 获取用户的媒体成功后，将媒体赋值给本地视频框 */
                localVideo.srcObject = stream;
                /** 设置音量无效 */
                //localVideo.volume = 0.8;
                /** 自动播放 无效 */
                //localVideo.play()
                /** 保存本地媒体数据流 */
                localStream = stream;
                /** 给本地媒体窗口绑定loadedmetadata事件，就是媒体数据加载完成后触发 */
                localVideo.addEventListener('loadedmetadata', function () {
                    /** 发布事件客户端连接 client-call */
                    publish('client-call', null)
                });

            }).catch(function (e) {
                alert(e);
            });
        }

    };
    /** ws的接收到消息事件 */
    ws.onmessage = function (e) {
        /** 解析json字符串 */
        var package = JSON.parse(e.data);
        /** 获取数据 */
        var data = package.data;
        /** 根据事件类型处理消息逻辑 */
        switch (package.event) {
            /** 客户端上线事件 */
            case 'client-call':
                console.log('call');
                /** 创建rtc连接，将本地节点广播给其他客户端，将本地流媒体绑定到rtc连接，然后绑定接收到对端媒体资源事件（播放） */
                icecandidate(localStream);
                /** 生成本地描述符，包括媒体格式和通道，以确保两端都能够理解并使用相同的媒体格式进行通信 */
                pc.createOffer({
                    offerToReceiveAudio: 1, /** 愿意接收对方的音频数据 */
                    offerToReceiveVideo: 1/** 愿意 接收对方的视频数据 */
                }).then(function (desc) {/** 获取描述符成功后 */
                    /** 保存自己的描述符 */
                    pc.setLocalDescription(desc).then(
                        function () {
                            /** 然后发布client-offer事件 ,发布本地流媒体的描述信息，*/
                            publish('client-offer', pc.localDescription);
                        }
                    ).catch(function (e) {
                        alert(e);
                    });
                }).catch(function (e) {
                    alert(e);
                });
                break;
            case 'client-answer':
                /** 收到对方客户端返回的描述符信息 */
                console.log('answer');
                /** 保存对方的描述符信息  */
                pc.setRemoteDescription(new RTCSessionDescription(data), function () {
                }, function (e) {
                    /** 使用的session来保存的 */
                    alert(e);
                });
                break;
            /** 接收到其他客户度发送的描述符信息 */
            case 'client-offer':
                console.log('offer');
                /** 我收到了别人发送的描述信息后，我还需要再次发送我自己的节点信息 */
                icecandidate(localStream);
                /** 收到对面的描述符信息之后，保存 */
                pc.setRemoteDescription(new RTCSessionDescription(data), function () {
                    /** 如果还没有和我对话的客户端 */
                    if (!answer) {
                        /** 创建一个回答，回答对面客户端，告诉对方本地的描述符 */
                        pc.createAnswer(function (desc) {
                                /** 保存自己的描述符 */
                                pc.setLocalDescription(desc, function () {
                                    /** 然后将自己的描述符告知其他的客户端 */
                                    publish('client-answer', pc.localDescription);
                                }, function (e) {
                                    alert(e);
                                });
                            }
                            , function (e) {
                                alert(e);
                            });
                        answer = 1;
                    }
                }, function (e) {
                    alert(e);
                });
                break;

            case 'client-candidate':
                /** 收到了其他客户端广播的节点信息 */
                console.log('candidate');
                /** 保存对方客户端的节点信息  */
                pc.addIceCandidate(new RTCIceCandidate(data), function () {
                }, function (e) {
                    alert(e);
                });
                break;
        }
    };
    /** 本地流媒体播放窗口 */
    const localVideo = document.getElementById('localVideo');
    /** 远程客户端流媒体播放窗口 */
    const remoteVideo = document.getElementById('remoteVideo');
    /** 设置getUserMedia ，因为有些浏览器不兼容 */
    navigator.getUserMedia = navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia;
    /** 内网穿透turn连接配置 */
    const configuration = {
        iceServers: [{
            urls: [
                // 'turn:business.swoole.com:3478?transport=udp',
                // 'turn:business.swoole.com:3478?transport=tcp',
                /** 本地的打洞服务,就是内网穿透 ，根据需求设置，请使用你自己的配置 ，如果是本地或者局域网则不需要使用内网穿透 */
                'turn:192.168.4.120:3478?transport=udp',
                'turn:192.168.4.120:3478?transport=tcp',
            ],
            username: 'kurento',
            credential: 'kurento'
        }]
    };
    var pc, localStream;

    /** ICE（Interactive Connectivity Establishment）是 WebRTC 中的一个重要概念，它是一种用于在浏览器之间建立实时通信连接的技术。ICE 是一种网络协议，用于确定浏览器之间可用的最佳网络路径，并在它们之间建立连接。
     ICE 通过使用各种网络协议和技术（如 STUN 和 TURN）来实现这一目标。它允许浏览器检测网络环境，并确定哪些网络协议和技术最适合于建立连接。ICE 还提供了一种方法，用于确定浏览器之间的最佳网络路径，并在它们之间建立高质量的连接。
     ICE 的主要目标是使实时通信更加可靠和高效，并允许浏览器在不同的网络条件下建立连接。它是 WebRTC 技术的重要组成部分，对于实现浏览器之间的实时通信至关重要。*/

    /**
     * ice服务的候选节点
     * 就是中间件服务器
     * 这个方法的作用是，创建rtc连接，获取本地节点信息，然后广播给其他的客户端，然后把本地的流媒体数据添加到rtc连接中（需要发送给其他客户端），
     * 最后注册接收到流媒体事件（收到流媒体数据后就播放）
     * @param localStream
     */
    function icecandidate(localStream) {
        /** 使用turn打洞服务作为数据中转服务器，创建连接 */
        //pc = new RTCPeerConnection(configuration);
        /** 调用rtc协议 */
        pc = new RTCPeerConnection();
        /** 设置完本地的sdp信息之后，把自己的节点信息广播出去，节点信息包括版本号，用户名，IP地址，端口，网络类型，session_id */
        pc.onicecandidate = function (event) {
            /** 如果有节点，则广播这个节点 */
            if (event.candidate) {
                publish('client-candidate', event.candidate);
            }
        };
        try {
            /** 把本地的流媒体添加到rtc连接中 */
            pc.addStream(localStream);
        } catch (e) {
            /** 没有找到资源，那就把本地的所有摄像头都添加到连接中 */
            /** 获取所有的摄像头 js获取摄像头权限实现拍照功能 https://blog.csdn.net/qq_45279180/article/details/111030620*/
            var tracks = localStream.getTracks();
            /** 将这些摄像头添加到本地流中 */
            for (var i = 0; i < tracks.length; i++) {
                /** 逐个添加摄像头 */
                pc.addTrack(tracks[i], localStream);
            }
        }
        /**  收到流媒体数据之后，将流媒体数据添加到播放窗口 */
        pc.onaddstream = function (e) {
            // $('#remoteVideo').removeClass('hidden');
            // $('#localVideo').remove();
            console.log("接收到对端流媒体信息，开始播放对方媒体数据")
            remoteVideo.srcObject = e.stream;
        };
    }

    /**
     * 发布消息
     * @param event
     * @param data
     */
    function publish(event, data) {
        ws.send(JSON.stringify({
            cmd: 'publish',
            subject: subject,
            event: event,
            data: data
        }));
    }

    /**
     * 订阅消息
     * @param subject
     */
    function subscribe(subject) {
        ws.send(JSON.stringify({
            cmd: 'subscribe',
            subject: subject
        }));
    }

    /**
     * 解析路由
     * @param name
     * @returns {string|null}
     */
    function getUrlParam(name) {
        var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
        var r = window.location.search.substr(1).match(reg);
        if (r != null) return unescape(r[2]);
        return null;
    }

    /**
     *
     * pc.createOffer：创建 offer 方法，方法会返回 SDP Offer 信息
     * pc.setLocalDescription 设置本地 SDP 描述信息
     * pc.setRemoteDescription：设置远端的 SDP 描述信息，即对方发过来的 SDP 信息
     * pc.createAnswer：远端创建应答 Answer 方法，方法会返回 SDP Offer 信息
     * pc.ontrack：设置完远端 SDP 描述信息后会触发该方法，接收对方的媒体流
     * pc.onicecandidate：设置完本地 SDP 描述信息后会触发该方法，打开一个连接，开始运转媒体流
     * pc.addIceCandidate：连接添加对方的网络信息
     * pc.setLocalDescription：将 localDescription 设置为 offer，localDescription 即为我们需要发送给应答方的 sdp，此描述指定连接本地端的属性，包括媒体格式
     * ————————————————
     * 版权声明：本文为CSDN博主「小油酱」的原创文章，遵循CC 4.0 BY-SA版权协议，转载请附上原文出处链接及本声明。
     * 原文链接：https://blog.csdn.net/qq_44476091/article/details/126505032
     * */

    /**
     * WebRTC 通信的全部流程包括以下步骤：
     * 1 建立连接：浏览器之间建立 RTCPeerConnection 对象，该对象用于管理 WebRTC 连接。创建offer
     * 2 交换证书：浏览器交换证书，以确保连接的安全性。一般是ssl证书
     * 3 协商媒体格式：浏览器之间协商媒体格式，以确定使用哪种音频和视频编码格式进行通信。创建answer
     * 4 创建媒体轨道：浏览器创建音频和视频轨道，以准备传输媒体数据。
     * 5 发送媒体数据：浏览器通过 RTCPeerConnection 对象发送媒体数据，对端浏览器接收并播放媒体数据。
     * 6 实时传输控制协议（RTCP）：浏览器之间使用 RTCP 协议来监控数据传输质量，并进行必要的调整。
     * 7 结束连接：当通信完成后，浏览器之间关闭 RTCPeerConnection 对象，结束 WebRTC 连接。
     *
     * 甲客户端首先创建一个连接，广播自己的节点信息（ip,端口等信息）
     *
     * */
</script>
</body>
</html>
