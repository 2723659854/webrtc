<?php

use Swoole\Http\Request;
use Swoole\Http\Response;

const WEBROOT = __DIR__ . '/web';

/** 保存渠道连接对应数组 ，就是每一个通道的订阅客户端数据 */
$subject_connnection_map = array();
/** 设置报错级别 */
error_reporting(E_ALL);
/** 开启一个协程 */
\Swoole\Coroutine\run(
    function () {
        /** 开启一个http服务 ,如果使用127.0.0.1访问，就不开启ssl，如果使用局域网或者外网，则必须使用ssl，否则无法调用摄像头和麦克风 */
        //$server = new Swoole\Coroutine\Http\Server('0.0.0.0', 9504, false);
        $server = new Swoole\Coroutine\Http\Server('0.0.0.0', 9504, true);
        $server->set(
            [
                'ssl_key_file' => __DIR__ . '/config/ssl.key',
                'ssl_cert_file' => __DIR__ . '/config/ssl.crt',
            ]
        );

        /** 逻辑处理函数 */
        $server->handle(
            '/',/** 根目录 */
            function (Request $req, Response $resp) {/** 请求，响应 */
                //websocket
                /** 如果请求要求升级协议为ws,*/
                if (isset($req->header['upgrade']) and $req->header['upgrade'] == 'websocket') {
                    /** 手动升级协议 */
                    $resp->upgrade();
                    /** 初始化响应 订阅的通道 */
                    $resp->subjects = array();
                    while (true) {
                        /** 接收客户端的数据 */
                        $frame = $resp->recv();
                        /** 数据为空 */
                        if (empty($frame)) {
                            break;
                        }
                        /** 解码接收到的数据 */
                        $data = json_decode($frame->data, true);
                        var_dump($data);
                        /** 解析对面的命令 */
                        switch ($data['cmd']) {
                            // 订阅主题
                            /** ws连接建立后，客户端会立即订阅某一个房间 ，就会走这个命令 */
                            case 'subscribe':
                                $subject = $data['subject'];
                                subscribe($subject, $resp);
                                break;
                            // 向某个主题发布消息
                            /** 发布消息 ，主要用于web-rtc两个客户端建立连接的时候交换地址用的 ，当客户端建立连接完成之后，传输流媒体文件不走ws ,那么ws服务相当于是网关 */
                            case 'publish':
                                $subject = $data['subject'];
                                $event = $data['event'];
                                $data = $data['data'];
                                publish($subject, $event, $data, $resp);
                                break;
                        }
                    }
                    /** 如果没有数据发送，则摧毁响应 ，就是断开连接，*/
                    destry_connection($resp);
                    return;
                }
                //http
                /** http 请求 获取请求地址 */
                $path = $req->server['request_uri'];
                if ($path == '/') {
                    /** 加载index.html 文件 */
                    $resp->end(exec_php_file(WEBROOT . '/index.html'));
                } else {
                    /** 检测文件是否存在 返回文件真实地址 */
                    $file = realpath(WEBROOT . $path);
                    if (false === $file) {
                        $resp->status(404);
                        $resp->end('<h3>404 Not Found</h3>');
                        return;
                    }
                    /** 如果文件并不属于本项目，则不可给用户执行，否则算入侵服务器 */
                    // Security check! Very important!!!
                    if (strpos($file, WEBROOT) !== 0) {
                        $resp->status(400);
                        return;
                    }
                    /** 如果文件是PHP文件，那么就返回文件执行后的结果 */
                    if (\pathinfo($file, PATHINFO_EXTENSION) === 'php') {
                        $resp->end(exec_php_file($file));
                        return;
                    }
                    /** 如果页面请求询问静态资源是否发生改变 */
                    if (isset($req->header['if-modified-since']) and !empty($if_modified_since = $req->header['if-modified-since'])) {
                        // Check 304.
                        /** 获取文件信息 */
                        $info = \stat($file);
                        /** 比较最后一次修改时间是否相等 */
                        $modified_time = $info ? \date(
                                'D, d M Y H:i:s',
                                $info['mtime']
                            ) . ' ' . \date_default_timezone_get() : '';
                        if ($modified_time === $if_modified_since) {
                            /** 如果文件修改时间相等，则说明文件没有发生变化，返回304，不需要重新下载静态资源文件 */
                            $resp->status(304);
                            /** 关闭连接 */
                            $resp->end();
                            return;
                        }
                    }
                    /** 静态资源文件发生了变化，则发送文件给客户端 */
                    $resp->sendfile($file);
                }
            }
        );
        /** 启动服务 */
        $server->start();
    }
);


// 订阅
function subscribe($subject, $connection)
{
    global $subject_connnection_map;
    /** 保存客户端订阅的渠道 */
    $connection->subjects[$subject] = $subject;
    /** 保存订阅某个渠道的所有客户端连接 */
    $subject_connnection_map[$subject][$connection->fd] = $connection;
}

// 取消订阅
function unsubscribe($subject, $connection)
{
    global $subject_connnection_map;
    /** 将客户端从这个渠道中删除 */
    unset($subject_connnection_map[$subject][$connection->fd]);
}

// 向某个主题发布事件
function publish($subject, $event, $data, $exclude)
{
    global $subject_connnection_map;
    /** 如果没有这个渠道 */
    if (empty($subject_connnection_map[$subject])) {
        return;
    }
    /** 遍历这个渠道下面的所有连接 */
    foreach ($subject_connnection_map[$subject] as $connection) {
        /** 排除客户端自己 */
        if ($exclude == $connection) {
            continue;
        }
        /** 将数据推送给客户端 */
        $connection->push(
            json_encode(
                array(
                    'cmd' => 'publish',# room.php 中接收到这个数据后，没有使用，可以屏蔽这个数据
                    'event' => $event,# 事件类型
                    'data' => $data,# 发送的数据
                )
            )
        );
    }
}

// 清理主题映射数组
function destry_connection($connection)
{
    /** 释放这个客户端订阅的所有渠道 */
    foreach ($connection->subjects as $subject) {
        unsubscribe($subject, $connection);
    }
}

/** 获取PHP执行完成后的结果 */
function exec_php_file($file)
{
    \ob_start();
    // Try to include php file.
    try {
        include $file;
    } catch (\Exception $e) {
        echo $e;
    }
    return \ob_get_clean();
}


