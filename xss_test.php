
<html>

    <script>
        //  XSS 漏水报告
        
        function report(xss_detail_element) {
            console.log('WARNING! EVAL ELEMENT .. '+xss_detail_element.tagName+'  '+xss_detail_element.src);
        }

    </script>
    
    <script>
        //  动态检测DOM 上变化来检测XSS
        
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
                            
                            if (dynamic_check_eval_event(new_element) || dynamic_check_eval_element(new_element)) {
                                console.log('WARNING ! Dynamic Create XSS ,inject DOM ..');
                            }
                        }
                    } else if ('attributes'==mutation.type) {
                        var new_attribute_value=eval('mutation.target.'+mutation.attributeName);
                        var change_attribute_element=mutation.target;
                        
                        if (dynamic_check_eval_event(change_attribute_element)) {
                            console.log('WARNING ! Dynamic Create XSS ,inject to attribute event ..');
                        }
                    }
                }); 
            });
            observer.observe(document.body,{
                'childList': true,
                'subtree': true,
                'attributes' : true
            });
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
    </script>
    
    <script>
        //  反射XSS 检测部分
        
        REFLECTED_XSS_INJECT_DOM=1;
        REFLECTED_XSS_INJECT_ELEMENT_OR_JAVASCRIPT=2;
        
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
        
        function split_string_space(input_string) {
            var next_space_index=input_string.indexOf(' ');
            var result=[];
            
            while (-1!=next_space_index) {
                result.push(input_string.substr(0,next_space_index));
                
                input_string=input_string.substr(next_space_index+1);
                next_space_index=input_string.indexOf(' ');
            }
            result.push(input_string);
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
                        analayis_index['reflected_data']=danger_parameter_index;
                    } else if ('\''==eval_flag || '"'==eval_flag) {
                        analayis_index['reflected_type']=REFLECTED_XSS_INJECT_ELEMENT_OR_JAVASCRIPT;
                        analayis_index['reflected_data']=danger_parameter_index;
                    }
                }
                result.push(analayis_index);
            }
            
            return result;
        }
        
        function find_first_eval_flag(parameter_value_string) {
            var flag_single_quotes_index=parameter_value_string.indexOf('\'');
            var flag_quotes_index=parameter_value_string.indexOf('"');
            var flag_less_than_signs_index=parameter_value_string.indexOf('<');
            var flag_right_than_signs_index=parameter_value_string.indexOf('>');
            
            var first_char=-1;
            
            first_char=flag_single_quotes_index;
            
            if (-1==first_char ||
                first_char>flag_quotes_index)
                first_char=flag_quotes_index;
            
            if (-1==first_char ||
                first_char>flag_less_than_signs_index)
                first_char=flag_less_than_signs_index;
            
            if (-1==first_char ||
                first_char>flag_right_than_signs_index)
                first_char=flag_right_than_signs_index;
            
            return first_char;
        }
            
        function check_insert_xss_code(parameter_value_string) {
            if (-1!=find_first_eval_flag(parameter_value_string))
                return true;
            
            return false;
        }
        
        function check_insert_xss_into_element(reflected_parameter) {
            if (REFLECTED_XSS_INJECT_DOM==reflected_parameter['reflected_type']) {
                var insert_dom_string=reflected_parameter['reflected_data'];
                var reg_matching=new RegExp('<\\w+>|<\\w+ |<\\w+\/','g');  
                /*
                    TIPS :
                    这里针对了<script>,<iframe>,<iframe/src=""/>
                    这样的XSS vector 做了过滤..
                */
                var reg_matching_result=insert_dom_string.match(reg_matching);
                
                for (var pick_element_tag_name=0;pick_element_tag_name<reg_matching_result.length;++pick_element_tag_name)
                    reg_matching_result[pick_element_tag_name]=reg_matching_result[pick_element_tag_name].substr(1,reg_matching_result[pick_element_tag_name].length-2);

                var build_query_selector_string='';

                for (var pick_element_tag_name=0;pick_element_tag_name<reg_matching_result.length;++pick_element_tag_name)
                    build_query_selector_string+=reg_matching_result[pick_element_tag_name]+' ';

                var search_insert_element_list=document.body.querySelectorAll(build_query_selector_string);

                if (search_insert_element_list.length) {
                    console.log('WARNING ! found reflected DOM XSS ..');
                    return true;
                }
            } else if (REFLECTED_XSS_INJECT_ELEMENT_OR_JAVASCRIPT==reflected_parameter['reflected_type']) {
                var insert_element_string=reflected_parameter['reflected_data'];
                
                if ('"'==insert_element_string ||
                    '\''==insert_element_string) {
                    /*
                        选择含有' 和" 符号的HTML 元素,一般在XSS 初期测试的时候会通过注入' 和" 号看看能否开闭HTML 属性
                        Example :

                        <img src="%input%" />
                                |  
                                v
                        正常情况下:<img src="123" />
                        转码情况下:<img src="123&quet" />
                        XSS 成功情况下:<img src="123" " />
                    */
                    var attribute_selector=document.body.querySelectorAll('[\\'+insert_element_string+']');
                    
                    if (attribute_selector.length) {
                        console.log('WARNING ! found reflected Attribute XSS -- Bypass Attribute String closed (" and \')..');
                        return true;
                    }
                } else {
                    var body_code=document.body.innerHTML;
                    var unencode_index=body_code.indexOf(insert_element_string);
                    var encode_index=body_code.indexOf(insert_element_string.replace(/</g,'%3C').replace(/>/g,'%3E'));
                    /*
                        TIPS: 这种情况还需要注意绕过属性闭合构造DOM XSS 的情况,有可能在插入的时候< > 会被过滤成字符编码..
                        Example:

                        " onerror="alert(\'element onerror() xss\');" /><script>alert(\'DOM XSS\');<//script>
                    */
                    
                    if (-1!=unencode_index) {
                        console.log('WARNING ! found reflected Attribute XSS ,unencode insert code ..');
                        return true;
                    } else if (-1!=encode_index) {
                        console.log('WARNING ! found reflected Attribute XSS ,encode insert code ..');
                        return true;
                    }
                    var attribute_list=split_string_space(insert_element_string);  //  使用分割属性的方法来匹配属性插入的元素
                    var valid_query_attribute_name_string='';

                    for (var attribute_list_index_=0;attribute_list_index_<attribute_list.length;++attribute_list_index_) {
                        var attribute_list_index=split_url_parameter_value(attribute_list[attribute_list_index_]);

                        if (undefined!=attribute_list_index['key'] && 
                           ('"'!=attribute_list_index['key'] || '\''!=attribute_list_index['key']))
                            valid_query_attribute_name_string+='['+attribute_list_index['key']+']';
                    }
                    var query_result=document.querySelectorAll(valid_query_attribute_name_string);

                    if (query_result.length) {
                        for (var query_result_index_=0;query_result_index_<query_result.length;++query_result_index_) {
                            var query_result_index=query_result[query_result_index_];
                        }
                        console.log('WARNING ! found reflected Attribute XSS');
                        return true;
                    }
                }
            }
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
                
                最后利用特征在document.querySelector 中发掘..
            */
            
            if (url_parameter_list.length) {
                var decode_parameter_list=[];
                var danger_parameter_value_list=[];
                
                for (var parameter_index_ in url_parameter_list) {
                    var parameter_index=url_parameter_list[parameter_index_];
                    
                    decode_parameter_list.push(unescape(parameter_index['value']).toLowerCase().trim());
                }
                for (var decode_parameter_list_index in decode_parameter_list)
                    if (check_insert_xss_code(decode_parameter_list[decode_parameter_list_index]))
                        danger_parameter_value_list.push(decode_parameter_list[decode_parameter_list_index]);
                
                if (danger_parameter_value_list.length) {
                    var reflected_parameter_list=analayis_reflected_parameter_xss(danger_parameter_value_list);
                    
                    for (var reflected_parameter_list_index in reflected_parameter_list) {
                        if (check_insert_xss_into_element(reflected_parameter_list[reflected_parameter_list_index])) {
                            console.log('WARNING reflected XSS ');
                        }
                    }
                }
            }
            return false;
        }
        
    </script>
    
    <script>
                
    </script>
   
    <body onload="check_reflected_xss()">
        
        <div id="xss_test_1">
            <!--
                反射XSS ,直接插入 <script>,<img>,<iframe>,混合插入 <script>,<img>,<iframe> 
                测试Payload:
                
                http://127.0.0.1/xss_test.php?xss_test_1=<script>alert('xss');</script>  --  基本测试
                http://127.0.0.1/xss_test.php?xss_test_1=<img src="" onerror="alert('xss')" />  --  DOM <img> 元素事件XSS 执行测试
                http://127.0.0.1/xss_test.php?xss_test_1=<iframe src="http://www.baidu.com" />  --  <iframe> 元素挂马测试
                http://127.0.0.1/xss_test.php?xss_test_1=<svg>/<script>alert('xss');</script>  --  组合HTML 元素绕过测试
                http://127.0.0.1/xss_test.php?xss_test_1=<div><a><img src="" onerror="alert('xss')" />  --  混合HTML 元素和img 事件绕过测试
            -->
            <?php
                if (isset($_GET['xss_test_1']))
                    echo $_GET['xss_test_1'];
            ?>
        </div>
        <div id="xss_test_2">
            <!--
                反射XSS 混合元素插入,混合属性和事件属性插入 <img> ,<img> 中混合属性和事件属性插入 <script>
                测试Payload:
                
                http://127.0.0.1/xss_test.php?xss_test_2="  --  初期XSS 绕过元素属性闭合测试
                http://127.0.0.1/xss_test.php?xss_test_2=" onerror="alert('xss');  --  元素事件XSS 测试
                http://127.0.0.1/xss_test.php?xss_test_2=' " onload="alert('xss');  --  元素事件XSS 误报BUG 测试
                http://127.0.0.1/xss_test.php?xss_test_2=" alt="change tips";  --  元素XSS 修改非事件属性测试
                http://127.0.0.1/xss_test.php?xss_test_2=" /><script>alert('xss');</script>  --  绕过元素之外构造DOM XSS 测试
                http://127.0.0.1/xss_test.php?xss_test_2=123  --  元素XSS 误报测试
            -->
            <?php
                if (isset($_GET['xss_test_2']))
                    echo '<img src="'.$_GET['xss_test_2'].'" />';
            ?>
        </div>
       
        <div id="xss_test_3"><!-- 储存XSS ,直接插入 <script> -->
           
        </div>
        
    </body>

</html>
