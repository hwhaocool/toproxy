# toproxy

> 用tornado实现的高性能代理服务器，涵盖了基本的method

*性能方面测试，toproxy在单进程模式下，新连接请求在3500 QPS*

> forked from [rfyiamcool/toproxy](https://github.com/rfyiamcool/toproxy)

感谢`rfyiamcool` 大佬的源码


### Future

1. 对每个请求，重新设置header  

因为我们的项目对接口的header有RSA签名校验，且规则已知

之前直接使用postman，很难自动生成签名

所以写了一个代理，来转发并处理header

2. 增加对PUT的支持  
原工程没有对`PUT`进行定制，现在增加了这一块的功能

3. 增加对`Post`的支持

4. 增加对`protobuf` 的支持
在body里面，输入`json`，当`header`设置了`type`为`protibuf`时，  
代理会自动把json转为protobuf序列化后的数据，发送到服务器



**快速启动**

```
python  -m toproxy/proxy -p 9999 
python  -m toproxy/proxy
::::Starting HTTP proxy on port 9999
...
```


### 注意
私钥我没有上传的哦，大家使用的时候需要改下代码，或者改下私钥名称

代码在`SignTool.py`的15行