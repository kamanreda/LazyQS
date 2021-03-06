package burp;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class BurpExtender implements IBurpExtender,ITab,IProxyListener{

    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static GUI gui;
    public static final List<LogEntry> httpLog = new ArrayList<LogEntry>();
    public static final List<LogEntry> paraLog = new ArrayList<LogEntry>();
    public static final List<LogEntry> detailLog = new ArrayList<LogEntry>();
    public static final Set<String> urlSet = new HashSet<String>();
    public String ExtenderName = "LazyQS";
    public static int Count = 0;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);
        callbacks.setExtensionName(ExtenderName);

        SwingUtilities.invokeLater(() -> {
            this.gui = new GUI();
            callbacks.addSuiteTab(BurpExtender.this);
            callbacks.registerProxyListener(BurpExtender.this);
            stdout.println(ExtenderName + " Load Success !");
        });

    }

    @Override
    public String getTabCaption() {
        return ExtenderName;
    }

    @Override
    public Component getUiComponent() {
        return gui.getPanel();
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest && (Config.sqlCheck_isRunning || Config.xssCheck_isRunning)){
            IHttpRequestResponse reprsp = message.getMessageInfo();
            IHttpService httpService = reprsp.getHttpService();
            String host = reprsp.getHttpService().getHost();
            //????????????
            if(!Utils.isMathch(Config.DOMAIN_REGX,host)){
                return;
            }

            //??????????????????
            String  url = helpers.analyzeRequest(httpService,reprsp.getRequest()).getUrl().toString();
            url = url.indexOf("?") > 0 ? url.substring(0, url.indexOf("?")) : url;
            String file = url.substring(url.lastIndexOf("."));
            if(Utils.isMathch(Config.SUFFIX_REGX, file)){
                return;
            }

            List<IParameter> paraList = helpers.analyzeRequest(reprsp).getParameters();
            String  scanUrl = helpers.analyzeRequest(httpService,reprsp.getRequest()).getUrl().toString();
            scanUrl = scanUrl.indexOf("?") > 0 ? scanUrl.substring(0, scanUrl.indexOf("?")) : scanUrl;
            for (IParameter parameter : paraList){
                scanUrl += parameter.getName();
            }
            String methodSign = helpers.analyzeRequest(reprsp).getMethod();
            scanUrl = methodSign + scanUrl;
            //??????hashset??????(url+????????????)???????????????????????????????????????????????????
            if (urlSet.add(scanUrl)){
                Count += 1;
            }else {
                return;
            }

            final IHttpRequestResponse reqrsp = message.getMessageInfo();

            synchronized (httpLog){
                Thread thread = new Thread(new Runnable() {
                    public void run() {
                        //????????????????????????????????????httpLog?????????state???????????????????????????????????????????????????
                        final int id = Count;  //????????????????????????????????????????????????Count
                        String sqlStat = "";
                        String xssStat = "";
                        int row = httpLog.size();
                        int length = reqrsp.getResponse().length;
                        String method = helpers.analyzeRequest(reqrsp).getMethod();
                        httpLog.add(new LogEntry(id,callbacks.saveBuffersToTempFiles(reqrsp),helpers.analyzeRequest(reqrsp).getUrl(),"","",method,length,"",0,"Run..."));
                        GUI.httpLogTable.getHttpLogTableModel().fireTableRowsInserted(row,row);

                        try {
                            if (Config.sqlCheck_isRunning && Config.xssCheck_isRunning){
                                sqlStat = VulCheck.sqlCheck(reqrsp, id, sqlStat);
                                xssStat = VulCheck.xssCheck(reqrsp, id, xssStat);
                            }else if (Config.sqlCheck_isRunning){
                                sqlStat = VulCheck.sqlCheck(reqrsp, id, sqlStat);
                            }else {
                                xssStat = VulCheck.xssCheck(reqrsp, id, xssStat);
                            }
                        }catch (Exception e){
                            e.printStackTrace();
                            stderr.println(e);
                        }
                        //??????httpLog??????
                        for (LogEntry logEntry : httpLog) {
                            if (logEntry.id == id) {
                                if (!sqlStat.isEmpty() || !xssStat.isEmpty()) {
                                    logEntry.setState(sqlStat+xssStat);
                                } else {
                                    logEntry.setState("end");
                                }
                            }
                        }
                        //??????http????????????????????????????????????????????????
                        GUI.httpLogTable.getHttpLogTableModel().fireTableDataChanged();
                        //????????????????????????
                        GUI.httpLogTable.setRowSelectionInterval(GUI.httpLogTable.getSign()-1,GUI.httpLogTable.getSign()-1);
                    }
                });
                thread.start();
            }
        }
    }
}
