
<html>

    <script>
        
        REFLECTED_XSS_INJECT_DOM=1;
        REFLECTED_XSS_INJECT_ELEMENT_OR_JAVASCRIPT=2;
        
        
        function report(xss_detail_element) {
            console.log('WARNING! EVAL ELEMENT .. '+xss_detail_element.tagName+'  '+xss_detail_element.src);
        }
        
        function dynamic_check_eval_event(element) {
            var black_element_event=['onerror','onload'];
            
            for (var element_attribute_index in element) {
                var event=eval('element.'+element_attribute_index);
                
                for (var black_element_event_index in black_element_event)
                    if (black_element_event[black_element_event_index]==element_attribute_index && 'function'==typeof event) 
                        return true;
            }
            return false;
        }
        
        function dynamic_check_eval_element(element) {
            var black_element_name=['SCRIPT','IFRAME'];
            
            for (var index in black_element_name)
                if (black_element_name[index]==element.tagName)
                    return true;
            
            return false;
        }
        
        function init() {
            //  init body observer object for monited dynamic element create ..
            var observer = new MutationObserver(function (mutations) {
                mutations.forEach(function (mutation) {
                    if ('childList'==mutation.type || 'subtree'==mutation.type) {
                        for (var index=0;index<mutation.addedNodes.length;++index) {
                            var new_element=mutation.addedNodes[index];
                            
                            if (dynamic_check_eval_event(new_element) || dynamic_check_eval_element(new_element))
                                report(new_element);
                        }
                    } else if ('attributes'==mutation.type) {
                        var new_attribute_value=eval('mutation.target.'+mutation.attributeName);
                        var change_attribute_element=mutation.target;
                        
                        if (dynamic_check_eval_event(change_attribute_element))
                            report(change_attribute_element);
                    }
                }); 
            });

            observer.observe(document.body,{
                'childList': true,
                'subtree': true,
                'attributes' : true
            });
            
            //  
            
            //  build element on body ..
            test_case();
        }
        
        function test_case() {
            /*
            var img=document.createElement('img');
            img.src='http://www.baidu.com/';
            img.onerror='alert("xss");';
            document.body.appendChild(img);
            */
            
            var test_script='<img src="http://www.baidu.com/" onerror="alert(\'img on error xss\');" />';
            test_script+='<img src="https://ss0.bdstatic.com/5aV1bjqh_Q23odCf/static/superman/img/logo/logo_white.png" />';
            test_script+='<img>';
            test_script+='<img src="https://ss0.bdstatic.com/5aV1bjqh_Q23odCf/static/superman/img/logo_top_ca79a146.png" onload="alert(\'img onload  xss\');" />';
            test_script+='<script>alert("script xss");';
            test_script+='</script';
            test_script+='>';
            test_script+='<nb>';
            test_script+='</nb>';
            
            document.body.innerHTML=test_script;
            
//            document.body.innerHTML+='
//    /*<script>';
            /*
            img.onerror='alert("xasd");';
            img.alt='trd';
    
            var script=document.createElement('script');
            document.body.appendChild(script);
            */
        }
        
        
        /*
        
        
            检测反射型XSS 逻辑..
        
        
        */
        
        function split_url_parameter_value(parameter_key_value) {
            var offset_equal_flag=parameter_key_value.indexOf('=');
            var result={};
            
            if (-1!=offset_equal_flag) {
                result['key']=parameter_key_value.substr(0,offset_equal_flag);
                result['value']=parameter_key_value.substr(offset_equal_flag+1);
            }
            return result;
        }
        
        function split_url_parameter_list() {
            var current_url=window.location.href;
            var is_exist_url_parameter=current_url.indexOf('?');
            var result=[];
            
            if (-1!=is_exist_url_parameter) {
                current_url=current_url.substr(is_exist_url_parameter+1);
                var every_parameter=current_url.indexOf('&');
                
                while (-1!=every_parameter) {
                    var parameter_key_value=current_url.substr(0,every_parameter);
                    var result_key_value_block=split_url_parameter_value(parameter_key_value);
                    
                    if (undefined==result_key_value_block.key)
                        return result;
                    
                    result.push(result_key_value_block);
                    current_url=current_url.substr(every_parameter+1);
                    every_parameter=current_url.indexOf('&');
                }
                var result_key_value_block=split_url_parameter_value(current_url);

                if (undefined!=result_key_value_block.key) 
                    result.push(result_key_value_block);
            }
            return result;
        }
        
        function analayis_reflected_parameter_xss(danger_parameter_list) {
            var result=[];
            
            for (var danger_parameter_list_index in danger_parameter_list) {
                var analayis_index={};
                var danger_parameter_index=danger_parameter_list[danger_parameter_list_index];
                var eval_flag_index=find_first_eval_flag(danger_parameter_index);
                
                if (-1!=eval_flag_index) {
                    var eval_flag=danger_parameter_index[eval_flag_index];
                    
                    if ('<'==eval_flag || '>'==eval_flag) {
                        analayis_index['reflected_type']=REFLECTED_XSS_INJECT_DOM;
                    } else if ('\''==eval_flag || '"'==eval_flag) {
                        analayis_index['reflected_type']=REFLECTED_XSS_INJECT_ELEMENT_OR_JAVASCRIPT;
                    }
                    analayis_index['reflected_data']=danger_parameter_index;
                }
                result.push(analayis_index);
            }
            
            return result;
        }
         
        function dom_child_element_recursion(element,parameter_analayis_information) {
            //  遍历DOM 树会卡在页面渲染性能的瓶颈上..
            /*
            
                TIPS -- XSS 过滤器会把注入到页面代码过滤掉,使得原来在URL 上的XSS 代码在DOM 上会改变
                Example :
                http://127.0.0.1/xss_test.php?xss_test_1=%3Cscript%3Ealert(%27xss%27);%3C/script%3E
                                                    |
                                                    v
                                            <script> <//script>
            
            */
            for (var parameter_index_ in parameter_analayis_information) {
                var parameter_index=parameter_analayis_information[parameter_index_];
                
                if (REFLECTED_XSS_INJECT_DOM==parameter_index['reflected_type']) {
                    var element_inner_html_code=element.innerHTML.toLowerCase();
                    
                    if (-1!=element_inner_html_code.indexOf(parameter_index['reflected_data']))
                        return true;
                } else if (REFLECTED_XSS_INJECT_ELEMENT_OR_JAVASCRIPT==parameter_index['reflected_type']) {
                    
                }
            }
            return false;
        }
        
        function find_first_eval_flag(parameter_value_string) {
            var flag_index=parameter_value_string.indexOf('<');
            if (-1!=flag_index)
                return flag_index;
            
            flag_index=parameter_value_string.indexOf('>');
            if (-1!=flag_index)
                return flag_index;
            
            flag_index=parameter_value_string.indexOf('\'');
            if (-1!=flag_index)
                return flag_index;
            
            flag_index=parameter_value_string.indexOf('"');
            if (-1!=flag_index)
                return flag_index;
            return -1;
        }
            
        function check_insert_xss_code(parameter_value_string) {
            if (-1!=find_first_eval_flag(parameter_value_string))
                return true;
            return false;
        }
        
        function check_reflected_xss() {
            var url_parameter_list=split_url_parameter_list();
            
            /*
            
                反射XSS Payload 集合
                
                注入代码到HTML DOM :
                http://xxx.com/?messages=<script>alert('xss');<//script>
                http://xxx.com/?messages=<img src='' onerror="alert('xss');" />
                http://xxx.com/?messages=<iframe src="http://xx.com/" />
                http://xxx.com/?messages=<a href="javascript:alert('xss');" />
                http://xxx.com/?messages=<a href="data:text/html,<script>alert('xss');<//script>" />
                注入代码到HTML Element Attribute 绕过:
                http://xxx.com/?messages=" /><script>alert('xss')<//script>
                http://xxx.com/?messages=" onerror="alert('xss');" />
                注入代码到javascript :
                http://xxx.com/?messages=';alert('xss');
            
                由上面的Payload 总结可以知道,反射型XSS 内带有< > " ' 关键字:
                还有对应的URL Encode 混淆:%3C <  %3E >  %22 "  %27 '
            
                URL 解析过程:
                http://xxx.com/a.php?arg=%3CScript%3ealert(%27xss%27);%3C/scRiPt%3e
                                            |
                                split_url_parameter_list()  
                                            |
                                            v
                        arg=%3CScript%3ealert(%27xss%27);%3C/scRiPt%3e
                                            |
                                        unescape()
                                            |
                                            v
                             arg=<Script>alert('xss');<//scRiPt>
                                            |
                                    URL.toLowerCase()
                                            |
                                            v
                             arg=<script>alert('xss');<//script>
                
                最后利用DOM 树遍历找特征..
                
            */
            
            if (url_parameter_list.length) {
                var decode_parameter_list=[];
                var danger_parameter_value_list=[];
                for (var parameter_index_ in url_parameter_list) {
                    var parameter_index=url_parameter_list[parameter_index_];
                    
                    decode_parameter_list.push(unescape(parameter_index['value']).toLowerCase().trim());
                }
                for (var index in decode_parameter_list)
                    if (check_insert_xss_code(decode_parameter_list[index]))
                        danger_parameter_value_list.push(decode_parameter_list[index]);
                
                console.log(danger_parameter_value_list);
                if (dom_child_element_recursion(document.body,analayis_reflected_parameter_xss(danger_parameter_value_list)))
                    console.log('WARNING reflected XSS ');
            }
            return false;
        }
        
    </script>
   
    <body onload="check_reflected_xss()">
       
        <div id="xss_test_1"><!-- 反射XSS ,直接插入 <script> -->
            <?php
                if (isset($_GET['xss_test_1']))
                    echo $_GET['xss_test_1'];
            ?>
        </div>
        <div id="xss_test_2"><!-- 反射XSS ,直接插入 <img> -->
           
        </div>
        <div id="xss_test_3"><!-- 反射XSS ,直接插入 <iframe> -->
           
        </div>
        <div id="xss_test_4"><!-- 反射XSS ,混合插入 <script> -->
           
        </div>
        <div id="xss_test_5"><!-- 反射XSS ,混合属性和事件属性插入 <img> -->
           
        </div>
        <div id="xss_test_6"><!-- 反射XSS ,<img> 中混合属性和事件属性插入 <script> -->
           
        </div>
        <div id="xss_test_7"><!-- 反射XSS ,混合元素插入 -->
           
        </div>
       
        <div id="xss_test_8"><!-- 储存XSS ,直接插入 <script> -->
           
        </div>
        
    </body>

</html>




























