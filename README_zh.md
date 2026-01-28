# LiteProxy

-R完整格式是:PROTOCOL://LOCAL_IP:LOCAL_PORT@CLIENT_LOCAL_HOST:CLIENT_LOCAL_PORT
协议PROTOCOL:tcp、udp、ptcp、pudp。
比如: -R "udp://:10053@:53" -R "tcp://:10800@:1080" -R ":8080@:80"
如果没有指定PROTOCOL，PROTOCOL默认为tcp，那么:-R ":8080@:80"默认为tcp;
LOCAL_IP为空默认是:0.0.0.0，CLIENT_LOCAL_HOST为空默认是:127.0.0.1;