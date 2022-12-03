# 闲言

首先欢迎认可的朋友一起丰富字典，目前更新了一些cms和oa的字典，后续有时间会逐渐补充。

--------

目前流行的批量漏洞验证，很多在请求时带有敏感字符，会被waf识别到，存在一定的弊端，而传统的目录扫描，可以说是效率很一般。两者结合，就有了新的想法，从漏洞验证的功能上退一步，从目录扫描的功能上进一步，诞生了此工具。

一切皆源自于效率提升，当面对大量的站点时，能在相对短时间内发现可能存在的漏洞，尽可能少被waf识别到，只发送GET请求，不带请求参数，判断返回包，借助指纹识别，判断出存在漏洞和可能存在漏洞。允许存在误报，但也都是经过判断后的误报，结果相对可控。

# 使用方法

半路出家，写的代码比较low，勉强能用，轻喷。。

```
> python3 vuldirscan_db.py -h
usage: vuldirscan_db.py [-h] [--url URL] [--urlfile URLFILE] [--thread THREAD] [--biglist] [--smalltlist]
                        [--bigtype BIGTYPE] [--smalltype SMALLTYPE]

optional arguments:
  -h, --help            show this help message and exit
  --url URL, -u URL     单个URL
  --urlfile URLFILE, -uf URLFILE
                        URL文件
  --thread THREAD, -t THREAD
                        进程数,默认30
  --biglist, -bl        大分类漏洞方向列表
  --smalltlist, -sl     某大分类下细分漏洞方向列表
  --bigtype BIGTYPE, -bt BIGTYPE
                        选择某大分类的漏洞方向
  --smalltype SMALLTYPE, -st SMALLTYPE
                        选择小分类的漏洞方向
```

可以只输入url或引用url文件，默认是对所有字典请求，也可以先查询字典里有哪些一级分类、二级分类，指定特定分类请求验证。请求结果实时输出、保存为excel两种。

```
例子：
# 默认全部请求
python3 vuldirscan_db.py -u http://127.0.0.1/
# 查询一级分类
python3 vuldirscan_db.py -bl
# 查询cms大类下有哪些二级分类
python3 vuldirscan_db.py -bt cms -sl
# 指定请求cms分类下的所有
python3 vuldirscan_db.py -bt cms
# 扫描WeiPHP CMS二级分类
python3 vuldirscan_db.py -bt -st WeiPHP

```

# 目前有的小功能

```
1.自动去URL后缀，包括末尾的/以及带的参数
2.漏洞请求前，先请求主URL，判断指纹，尽可能减少请求量
3.指纹识别通过返回包是否包含判断，每类框架，指纹识别可写多个，为或关系，尽可能匹配全
4.通过返回包判断特征，是否存在漏洞，可写多个特征，多个之间的关系通过数据库字段switch决定，true为与，false为或，其他的特征也可添加多个，以提高准确度，多个关系亦可通过swich字段添加相应内容决定。
```