<?php include __DIR__ . '/../config.php'?>
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
    <video id="localVideo" autoplay style="width:800px;height:400px;" muted="true"></video>
    <br>
    <video id="remoteVideo" autoplay style="width:800px;height:400px;"></video>
<!--    class="hidden"-->
</div>

<script src="assets/js/jquery-3.2.1.min.js"></script>
<script src="assets/js/bootstrap.js"></script>
<script src="assets/js/adapter.js"></script>

<script type="text/javascript">
    /** ws 连接地址 */
    var WS_ADDRESS = '<?php echo $SIGNALING_ADDRESS;?>';

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
    var subject = 'private-video-room-'+cid;

    /** 建立与websocket的连接 */
    var ws = new WebSocket(WS_ADDRESS);
    // console.log(ws);
    ws.onopen = function(){
        console.log('ws连接成功');
        /** 订阅信道 ，订阅通道 */
        subscribe(subject);
        /** 获取正在使用的媒体设备，这里会弹出对话框让用户选择需要分享的窗口，可以选择浏览器的某一个标签，可以使命令行窗口，可以使打开的文档，编辑器等等 */
        navigator.mediaDevices.getDisplayMedia({
            /** 获取音频 */
            audio: true,
            /** 获取视频 */
            video: true
        }).then(function (stream) {
            /** 获取用户的媒体成功后，将媒体赋值给本地视频框 */
            localVideo.srcObject = stream;
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
    };
    /** ws的接收到消息事件 */
    ws.onmessage = function(e){
        /** 解析json字符串 */
        var package = JSON.parse(e.data);
        /** 获取数据 */
        var data = package.data;
        /** 根据事件类型处理消息逻辑 */
        switch (package.event) {
            /** 客户端请求连接事件 */
            case 'client-call':
                console.log('call');
                /** 获取本地的流媒体资源，可以是浏览器，*/
                icecandidate(localStream);
                /** 获取本地流媒体传输参数， */
                pc.createOffer({
                    offerToReceiveAudio: 1,/** 愿意接收对方的音频数据 */
                    offerToReceiveVideo: 1/** 愿意 接收对方的视频数据 */
                }).then(function (desc) {
                    /** ICE 是 WebRTC 中的一种网络协议，用于在浏览器之间建立点对点的 P2P 连接。ICE 候选者是在连接建立过程中，浏览器向对方浏览器发送的一组候选者信息，包括 IP 地址、端口号等。*/
                    /** 就是将对方设置为候选者 ，保存对方的ip ,端口，然后才能点对点的通信 ，否则不能实现点对点的通信，只能使用服务器中转消息 */
                    pc.setLocalDescription(desc).then(
                        function () {
                            /** 然后发布client-offer事件 ,发布本地流媒体的描述，通知其他客户端说，我上线了 */
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
                console.log('answer');
                /** 应答事件，设置远程客户端描述，就是保存远程客户端的ip端口等信息  */
                pc.setRemoteDescription(new RTCSessionDescription(data),function(){}, function(e){
                    /** 使用的session来保存的 */
                    alert(e);
                });
                break;
            case 'client-offer':
                console.log('offer');

                icecandidate(localStream);
                /** 对面有客户端上线 */
                pc.setRemoteDescription(new RTCSessionDescription(data), function(){
                    /** 如果没有和我对话的客户端 */
                    if (!answer) {
                        /** 创建一个会话的对象 */
                        pc.createAnswer(function (desc) {
                            /** 将对方的信息保存到本地 */
                                pc.setLocalDescription(desc, function () {
                                    /** 发布客户端回答事件 */
                                    publish('client-answer', pc.localDescription);
                                }, function(e){
                                    alert(e);
                                });
                            }
                        ,function(e){
                            alert(e);
                        });
                        answer = 1;
                    }
                }, function(e){
                    alert(e);
                });
                break;

            case 'client-candidate':
                console.log('candidate');
                /** 添加对方的网络信息  */
                pc.addIceCandidate(new RTCIceCandidate(data), function(){}, function(e){alert(e);});
                break;
        }
    };

    const localVideo = document.getElementById('localVideo');
    const remoteVideo = document.getElementById('remoteVideo');

    navigator.getUserMedia = navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia;

    // $(function (){
    //     alert("页面加载完毕")
    //
    // })

    const configuration = {
        iceServers: [{
            urls: [
                'turn:business.swoole.com:3478?transport=udp',
                'turn:business.swoole.com:3478?transport=tcp',
                /** 本地的打洞服务 */
                //'turn:localhost:3478?transport=udp',
                //'turn:localhost:3478?transport=tcp',
            ],
            username: 'kurento',
            credential: 'kurento'
        }]
    };
    var pc, localStream;

    /**
     * ice服务的候选节点
     * 就是中间件服务器
     * @param localStream
     */
    function icecandidate(localStream) {
        /** 使用turn打洞服务作为数据中转服务器，创建连接 */
        //pc = new RTCPeerConnection(configuration);
        pc = new RTCPeerConnection();
        /** 获取到候选节点数据之后 */
        pc.onicecandidate = function (event) {
            /** 如果有节点，则广播这个节点 */
            if (event.candidate) {
                publish('client-candidate', event.candidate);
            }
        };
        try {
            /** 添加流媒体 */
            pc.addStream(localStream);
        } catch (e) {
            /** 获取所有的摄像头 */
            var tracks = localStream.getTracks();
            /** 将这些摄像头添加到本地流中 */
            for (var i = 0; i < tracks.length; i++) {
                pc.addTrack(tracks[i], localStream);
            }
        }
        /** 添加流媒体成功之后 ，设置远程聊天窗口的src等播放属性 */
        pc.onaddstream = function (e) {
            // $('#remoteVideo').removeClass('hidden');
            // $('#localVideo').remove();
            remoteVideo.srcObject = e.stream;
        };
    }

    function publish(event, data) {
        ws.send(JSON.stringify({
            cmd:'publish',
            subject: subject,
            event:event,
            data:data
        }));
    }

    function subscribe(subject) {
        ws.send(JSON.stringify({
            cmd:'subscribe',
            subject:subject
        }));
    }

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

</script>
</body>
</html>
