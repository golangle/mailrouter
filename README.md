# mail router

在naivemail基础上孵化出 mailrouter!

1、mailrouter 增加了状态控制，严格控制命令序列执行的状态顺序。不允许未经 HELO 或者 EHLO 发送其他命令。
2、实现了单端口(25端口)明文连接，通过 starttls 命令升级到 TLS加密连接。
3、服务启动自动生成认证密钥，无需手动生成。
4、支持 Enhanced Status Code。
5、支持多附件。
6、增强安全机制。
* 发送数据请求，限时30秒，如果读取的数据非常长，可能会导致阻塞，设置超时机制，防止恶意阻塞。
* 设置30秒的读取超时并限制读取长度，防止内存耗尽攻击。
7、体积非常小，仅有 7.2M 。
8、golang原生开发，不依赖其他开发库 。
9、支持docker安装 。


## docker 运行
```
docker run -p 25:25 -v /data/volumes/mail-router/emails:/emails -v /data/volumes/mail-router/cert:/cert -v /etc/localtime:/etc/localtime:ro -v /etc/timezone:/etc/timezone:ro --label description="电子邮件路由" --label 启动日期="2025-12-27"  -d --name mailrouter  go-mail-router
```

## Todo List
1、增加对 EHLO 或者 HELO 携带域名参数的检查；
2、对域名参数进行 SPF 验证，验证未通过的全部加入永久黑名单。
3、根据需要对认证签名文件实现动态匹配和加载。
