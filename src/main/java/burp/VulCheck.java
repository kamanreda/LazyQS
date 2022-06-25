package burp;


import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VulCheck {

    public static String sqlCheck(IHttpRequestResponse reqrsp, int count, String stat){

        //payload处理
        LinkedHashSet<String> payloads = new LinkedHashSet<String>();
        payloads.add("'");
        payloads.add("''");
        if(Config.loadPayload_isRunning){
            //读取text
            payloads.addAll(Arrays.asList(Config.SQLPAYLOAD));
        }

        //解析参数
        //获取请求体
        IRequestInfo req = BurpExtender.helpers.analyzeRequest(reqrsp);
        //获取请求头
        List<String> headers = BurpExtender.helpers.analyzeRequest(reqrsp).getHeaders();
        //获取参数列表
        List<IParameter> parameters = BurpExtender.helpers.analyzeRequest(reqrsp).getParameters();
        //构造新请求需要的参数
        byte[] new_Request = reqrsp.getRequest();
        IHttpService iHttpService = reqrsp.getHttpService();
        //list存放每次解析的参数和payload
        ArrayList<String> list = new ArrayList<String>();
        //解析参数发包
        for (IParameter ipara : parameters) {
            int time_1 = 0,time_2 = 0;
            list.clear();
            if (ipara.getType() == 0 || ipara.getType() == 1 || ipara.getType() == 6) {
                String key = ipara.getName();
                String value = ipara.getValue();

                if (ipara.getType() == 0 || ipara.getType() == 1) {
                     if (value.contains("{") || value.contains("%7b") || value.contains("%7B")) {
                        //url和请求体中为 aa=bb&cc={{"qq":"22'","ww":"33"}}的情况
                        ArrayList<Integer> length = new ArrayList<Integer>();
                        String data = URLDecoder.decode(value);
                        ArrayList<String> value_json = Utils.parseJson(data, payloads, list);
                        for (int i=0;i<value_json.size();i++) {
                            String vulnerable = "";
                            String str = value_json.get(i);

                            //如果是get型请求，进行url编码
                            if (ipara.getType() == 0) {
                                str = URLEncoder.encode(str);
                            }
                            IParameter newPara = BurpExtender.helpers.buildParameter(key, str, ipara.getType());
                            byte[] newRequest = BurpExtender.helpers.updateParameter(new_Request, newPara);
                            time_1 = (int) System.currentTimeMillis();
                            //发送请求并获取响应
                            IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(iHttpService, newRequest);
                            time_2 = (int) System.currentTimeMillis();
                            String resp = BurpExtender.helpers.bytesToString(requestResponse.getResponse());
                            //匹配响应中的sql报错，尽量不用正则，使用太耗时，剩下判断不了的就靠判断长度
                            for (String s : Config.SQL){
                                if(resp.indexOf(s) > 0){
                                    vulnerable = "vulnerable";
                                    stat = "SQL";
                                    break;
                                }
                            }

                            //把每次发包的响应长度值存储
                            length.add(requestResponse.getResponse().length);
                            //判断长度变化，当数组元素为偶数时才进行判断
                            if (length.size() % 2 == 0){
                                //如果双引号长度和原包长度相等，且与单引号长度不相等，则可能存在漏洞
                                if (reqrsp.getResponse().length == length.get(i) && (!length.get(i).equals(length.get(i-1)))){

                                    stat = stat.equals("SQL") ? stat : "sql?";
                                    vulnerable = vulnerable.equals("vulnerable") ? vulnerable : "possible";

                                }else if(!length.get(i).equals(length.get(i-1)) && (Math.abs(length.get(i)-length.get(i-1)) != 1)){
                                    stat = (stat.equals("SQL") || stat.equals("sql?")) ? stat : "?";
                                    vulnerable = vulnerable.equals("vulnerable") ? vulnerable : "check";
                                }
                            }

                            //获取当前正在注入的参数
                            String[] strings = list.get(i).split(":");
                            String a = strings[0];  //参数值
                            String b = strings[1];  //payload
                            BurpExtender.paraLog.add(new LogEntry(count,BurpExtender.callbacks.saveBuffersToTempFiles(requestResponse),BurpExtender.helpers.analyzeRequest(requestResponse).getUrl(),a,b,"",requestResponse.getResponse().length,vulnerable,(time_2-time_1),""));

                        }
                    }else {
                        //正常情况
                        if (value.matches("[0-9]+")) {//用于判读参数的值是否为纯数字
                            payloads.add("-1");
                            payloads.add("-0");
                        }
                        //获取每次发包的响应长度
                        ArrayList<Integer> length = new ArrayList<Integer>();
                        int i = 0;
                        for (String payload : payloads) {
                            String new_value;
                            String vulnerable = "";
                            if (ipara.getType() == 0) {
                                new_value = URLEncoder.encode(value + payload);
                            } else {
                                new_value = value + payload;
                            }

                            IParameter newPara = BurpExtender.helpers.buildParameter(key, new_value, ipara.getType());
                            byte[] newRequest = BurpExtender.helpers.updateParameter(new_Request, newPara);
                            time_1 = (int) System.currentTimeMillis();
                            IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(iHttpService, newRequest);
                            time_2 = (int) System.currentTimeMillis();
                            String resp = BurpExtender.helpers.bytesToString(requestResponse.getResponse());

                            //匹配响应中的sql报错
                            for (String s : Config.SQL){
                                if(resp.indexOf(s) > 0){
                                    vulnerable = "vulnerable";
                                    stat = "SQL";
                                    break;
                                }
                            }
                            //把每次发包的响应长度值存储
                            length.add(requestResponse.getResponse().length);
                            //判断长度变化，当数组元素为偶数时才进行判断
                            if (length.size() % 2 == 0){
                                //如果双引号长度和原包长度相等，且与单引号长度不相等，则可能存在漏洞
                                if (reqrsp.getResponse().length == length.get(i) && (!length.get(i).equals(length.get(i-1)))){

                                    stat = stat.equals("SQL") ? stat : "sql?";
                                    vulnerable = vulnerable.equals("vulnerable") ? vulnerable : "possible";

                                }else if(!length.get(i).equals(length.get(i-1)) && (Math.abs(length.get(i)-length.get(i-1)) != 1)){
                                    stat = (stat.equals("SQL") || stat.equals("sql?")) ? stat : "?";
                                    vulnerable = vulnerable.equals("vulnerable") ? vulnerable : "check";
                                }
                            }
                            i++;
                            BurpExtender.paraLog.add(new LogEntry(count,BurpExtender.callbacks.saveBuffersToTempFiles(requestResponse),BurpExtender.helpers.analyzeRequest(requestResponse).getUrl(),value,payload,"",requestResponse.getResponse().length,vulnerable,(time_2-time_1),""));

                        }
                    }
                }else {
                    //获取请求体
                    int bodyOffset = req.getBodyOffset();
                    String request = BurpExtender.helpers.bytesToString(new_Request);
                    String body = request.substring(bodyOffset);
                    //获取每次发包的响应长度
                    ArrayList<Integer> length = new ArrayList<Integer>();
                    //遍历json请求体，修改参数
                    ArrayList<String> value_json = Utils.parseJson(body, payloads, list);
                    for (int i=0;i<value_json.size();i++){
                        String vulnerable = "";
                        byte[] new_httpRequest = BurpExtender.helpers.buildHttpMessage(headers, value_json.get(i).getBytes());
                        time_1 = (int) System.currentTimeMillis();
                        IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(iHttpService, new_httpRequest);
                        time_2 = (int) System.currentTimeMillis();
                        String resp = BurpExtender.helpers.bytesToString(requestResponse.getResponse());
                        //匹配响应中的sql报错
                        for (String s : Config.SQL){
                            if(resp.indexOf(s) > 0){
                                vulnerable = "vulnerable";
                                stat = "SQL";
                                break;
                            }
                        }

                        //把每次发包的响应长度值存储
                        length.add(requestResponse.getResponse().length);
                        //判断长度变化，当数组元素为偶数时才进行判断
                        if (length.size() % 2 == 0){
                            //如果双引号长度和原包长度相等，且与单引号长度不相等，则可能存在漏洞
                            if (reqrsp.getResponse().length == length.get(i) && (!length.get(i).equals(length.get(i-1)))){

                                stat = stat.equals("SQL") ? stat : "sql?";
                                vulnerable = vulnerable.equals("vulnerable") ? vulnerable : "possible";

                            }else if(!length.get(i).equals(length.get(i-1)) && (Math.abs(length.get(i)-length.get(i-1)) != 1)){
                                stat = (stat.equals("SQL") || stat.equals("sql?")) ? stat : "?";
                                vulnerable = vulnerable.equals("vulnerable") ? vulnerable : "check";
                            }
                        }
                        String[] strings = list.get(i).split(":");
                        String a = strings[0];
                        String b = strings[1];
                        BurpExtender.paraLog.add(new LogEntry(count,BurpExtender.callbacks.saveBuffersToTempFiles(requestResponse),BurpExtender.helpers.analyzeRequest(requestResponse).getUrl(),a,b,"",requestResponse.getResponse().length,vulnerable,(time_2-time_1),""));

                    }
                    //因为请求体是纯json，直接在上面已经遍历跑完了，不需要遍历系统解析的参数
                    break;
                }
            }
        }
        return stat;
    }

    public static String xssCheck(IHttpRequestResponse reqrsp, int count, String stat){
        List<IParameter> paraList = BurpExtender.helpers.analyzeRequest(reqrsp).getParameters();
        ArrayList<String> payloads = new ArrayList<String>();
        payloads.add("<\";)('>");
        if(Config.loadPayload_isRunning){
            //读取text
            payloads.addAll(Arrays.asList(Config.XSSPAYLOAD));
        }
        byte[] new_Request = reqrsp.getRequest();
        IHttpService iHttpService = reqrsp.getHttpService();
        for (IParameter para : paraList){
            String key = para.getName();
            String value = para.getValue();
            //只检查get请求
            if (para.getType() == 0){
                for (String payload : payloads){
                    String new_value = URLEncoder.encode(value+payload);
                    IParameter newPara = BurpExtender.helpers.buildParameter(key, new_value, para.getType());
                    byte[] newRequest = BurpExtender.helpers.updateParameter(new_Request, newPara);
                    IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(iHttpService, newRequest);
                    String resp = BurpExtender.helpers.bytesToString(requestResponse.getResponse());
                    if (resp.contains(payload) || resp.contains(URLDecoder.decode(payload))){
                        stat = "xss";
                        BurpExtender.paraLog.add(new LogEntry(count,BurpExtender.callbacks.saveBuffersToTempFiles(requestResponse),BurpExtender.helpers.analyzeRequest(requestResponse).getUrl(),key,payload,"",requestResponse.getResponse().length,"xss",0,""));
                    }
                }
                if (!stat.isEmpty()){
                    break;
                }
            }
        }
        return stat;
    }
}
