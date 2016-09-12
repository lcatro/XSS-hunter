
###XSS-hunter
---

目前国内的Android APP 较为广泛使用Webview 的方法快速开发产品,如果产品本身在Webview 上的设计出现了安全问题,很有可能会产生XSS 跨站甚至是跨域的脚本注入(对于Webview 上展示的页面来说,出现XSS 的危害不亚于RCE 远程代码执行[PK AV 浏览器专辑:疗一疗本土瘤览器](https://github.com/lcatro/Hacker_Document/blob/master/Browser/%E7%96%97%E4%B8%80%E7%96%97%E6%9C%AC%E5%9C%9F%E7%98%A4%E8%A7%88%E5%99%A8.pdf),所有的Webview 上的元素和执行逻辑都可以被XSS 所控制,如果XSS 出现在特权域,同样也可以导致RCE 安全问题[KCon-2013 黑哥议题:去年跨过的客户端](https://github.com/lcatro/Hacker_Document/blob/master/Browser/%E5%8E%BB%E5%B9%B4%E8%B7%A8%E8%BF%87%E7%9A%84%E5%AE%A2%E6%88%B7%E7%AB%AF.pptx)).`XSS-hunter` 通过分析Webview 页面上的XSS 特征,向开发人员提供APP 在发布之后来自用户使用的过程中回传有关APP Webview 里面的XSS 信息收集报告,加速热补丁更新速度,及时止损..<br/>
下面是常见的反射型XSS 测试用例:<br/>

    http://127.0.0.1/xss_test.php?xss_test_1=<script>alert('xss');</script>  --  基本测试
    http://127.0.0.1/xss_test.php?xss_test_1=<img src="" onerror="alert('xss')" />  --  DOM <img> 元素事件XSS 执行测试
    http://127.0.0.1/xss_test.php?xss_test_1=<iframe src="http://www.baidu.com" />  --  <iframe> 元素挂马测试
    http://127.0.0.1/xss_test.php?xss_test_1=<svg>/<script>alert('xss');</script>  --  组合HTML 元素绕过测试
    http://127.0.0.1/xss_test.php?xss_test_1=<div><a><img src="" onerror="alert('xss')" />  --  混合HTML 元素和img 事件绕过测试
    http://127.0.0.1/xss_test.php?xss_test_2="  --  初期XSS 绕过元素属性闭合测试
    http://127.0.0.1/xss_test.php?xss_test_2=" onerror="alert('xss');  --  元素事件XSS 测试
    http://127.0.0.1/xss_test.php?xss_test_2=' " onload="alert('xss');  --  元素事件XSS 误报BUG 测试
    http://127.0.0.1/xss_test.php?xss_test_2=" alt="change tips";  --  元素XSS 修改非事件属性测试
    http://127.0.0.1/xss_test.php?xss_test_2=" /><script>alert('xss');</script>  --  绕过元素之外构造DOM XSS 测试
    http://127.0.0.1/xss_test.php?xss_test_2=123  --  元素XSS 误报测试

在测试中全部通过,`XSS-hunter` 的检测效果:<br/>
![example](https://raw.githubusercontent.com/lcatro/XSS-hunter/master/example.png)
