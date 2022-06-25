package burp;

import java.net.URL;

//日志java bean
public class LogEntry {
    final int id;
    final String method;
    final IHttpRequestResponsePersisted requestResponse;
    final URL url;
    final String parameter;
    final String payload;
    final int length;
    final String vulnerable;
    final int times;
    String state;

    LogEntry(int id, IHttpRequestResponsePersisted requestResponse, URL url, String parameter,String payload, String method, int length, String vulnerable, int times, String state){
        this.id = id;
        this.requestResponse = requestResponse;
        this.url = url;
        this.parameter = parameter;
        this.payload = payload;
        this.method = method;
        this.length = length;
        this.vulnerable = vulnerable;
        this.times = times;
        this.state = state;
    }

    public void setState(String state){
        this.state = state;
    }
}
