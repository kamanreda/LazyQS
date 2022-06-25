package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {

    public static boolean isMathch(String regx,String str){
        Pattern pat = Pattern.compile("([\\w]+[\\.]|)("+regx+")",Pattern.CASE_INSENSITIVE);//正则判断
        Matcher mc= pat.matcher(str);//条件匹配
        if(mc.find()){
            return true;
        }else{
            return false;
        }
    }

    public static ArrayList<String> parseJson(String data, LinkedHashSet<String> payloads, ArrayList<String> list) {
        JSONObject jsonData = JSON.parseObject(data);   //{"cc":{"qq":"22","ww":"33"}}
        ArrayList<String> value_json = new ArrayList<>();
        String json = "";

        for (Map.Entry<String, Object> entry : jsonData.entrySet()) {
            Object jsonValue = entry.getValue();
            //判断这个json参数类型，是整数就不注入引号，直接跳过，因为整数插入引号就强转成字符串了，不然json解析报错
            //不是的转换为字符型，为下面判断是否嵌套做准备
            if (jsonValue instanceof Integer) {
                continue;
            }else {
                json = jsonValue.toString();
            }
            //判断是否嵌套，是的话调用自身解析
            if (json.contains("{")){   //{"qq":"22","ww":"33"}
                ArrayList<String> tmpJsonList = parseJson(json, payloads,list);//{"{"qq":"22'","ww":"33"}","{"qq":"22''","ww":"33"}"}
                //把返回的修改后的嵌套json列表值整合到当前json里，并添加到当前json列表
                for (String str : tmpJsonList){
                    entry.setValue(JSON.parse(str));
                    value_json.add(jsonData.toJSONString());
                }
                //复原参数值，这样每一轮遍历只修改当前参数的值
                entry.setValue(jsonValue);
            }else {
                for (String payload : payloads){
                    //拼接payload进去，构造新的json字符串
                    entry.setValue(json + payload);
                    list.add(json+":"+payload);
                    //把改好的json字符串添加进数组
                    value_json.add(jsonData.toJSONString());
                }
                //复原参数值，这样每一轮遍历只修改当前参数的值
                entry.setValue(jsonValue);
            }
        }
        //返回修改后的所有json字符串数组{“json1”,"json2","json3"}
        return value_json;
    }

}
