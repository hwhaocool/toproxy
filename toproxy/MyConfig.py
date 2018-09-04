#coding:utf-8
import simplejson
import re

class MyConfig:

    __json = None

    def __init__(self):
        """构造方法"""
        f = open("config.json", "r")

        self.__json = simplejson.load(f)
        f.close()

    def getAccept(self, url):
        """匹配URL，得到对应的Accept"""

        accecptJson = self.__json['accept']
        for k, v in accecptJson.items():
            m = re.match(k, url)
            if m:
                print "url %s match %s" % (url, k)
                return v
        return None

if __name__ == '__main__':
    s = MyConfig()
    print(s.getAccept("/v1/h5/house/info"))
    print(s.getAccept("x/v1/h5/house/info"))