# toproxy

> 用tornado实现的高性能代理服务器，涵盖了基本的method

*性能方面测试，toproxy在单进程模式下，新连接请求在3500 QPS*

> forked from [rfyiamcool/toproxy](https://github.com/rfyiamcool/toproxy)

感谢`rfyiamcool` 大佬的源码


### Future

对每个请求，重新设置header
因为我们的项目对接口的header有RSA签名校验，且规则已知

之前直接使用postman，很难自动生成签名

所以写了一个代理，来转发并处理header



**快速启动**

```
python  -m toproxy/proxy -p 9999 
python  -m toproxy/proxy
::::Starting HTTP proxy on port 9999
...
```

