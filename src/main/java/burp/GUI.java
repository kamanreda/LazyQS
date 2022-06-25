package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.ActionEvent;

public class GUI implements IMessageEditorController{
    private JTabbedPane tabs;
    private JPanel contentPane, payloadPane;
    private JLabel lbDomain;
    private JTextField tfDomain;
    private JLabel lbExcludeSuffix;
    private JTextField tfExcludeSuffix;
    private JSplitPane jSplitPane;
    private JPanel centerPane;

    private JToggleButton btnSql;
    private JToggleButton btnXss;
    private JToggleButton btnPayload;

    public static JTabbedPane bottomTabs;
    public static IMessageEditor requestViewer;
    public static IMessageEditor responseViewer;
    public static IHttpRequestResponse currentlyDisplayedItem;
    public static HttpLogTable httpLogTable;
    public static ParaLogTable paraLogTable;

//    测试用主窗口
//    public static void main(String[] args) {
//        //新建窗体
//        JFrame jFrame = new JFrame();
//        //设置窗体大小
//        jFrame.setBounds(600,300,1200,900);
//        //设置面板
//        jFrame.setContentPane(new GUI().getPanel());
//        //开启关闭按钮
//        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//        //显示界面
//        jFrame.setVisible(true);
//    }

    public JTabbedPane getPanel(){
        //选项卡
        JTabbedPane tabs = new JTabbedPane();

        /***************************************check面板******************************************/
        //check面板，也是主面板
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5)); //设置边界，表示面板与四周的距离
        contentPane.setLayout(new BorderLayout(0, 0));
        jSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //分割面板


        //中间显示面板，http日志和参数日志
        centerPane = new JPanel();
        centerPane.setBorder(new EmptyBorder(5,0,0,0));
        //centerPane.setLayout(new BorderLayout());
        centerPane.setLayout(new FlowLayout());

        //左边http日志
        HttpLogTableModel httpLogTableModel = new HttpLogTableModel();
        httpLogTable = new HttpLogTable(httpLogTableModel);
        JScrollPane jspTemp = new JScrollPane(httpLogTable);
        jspTemp.setPreferredSize(new Dimension(550,400));

        //中间指向符号
        JLabel point = new JLabel("==>");
        point.setHorizontalAlignment(SwingConstants.CENTER);  //让标签居中显示

        //右边参数日志
        ParaLogTableModel paraLogTableModel = new ParaLogTableModel();
        paraLogTable = new ParaLogTable(paraLogTableModel);
        JScrollPane jspTemp2 = new JScrollPane(paraLogTable);
        jspTemp2.setPreferredSize(new Dimension(550,400));

        //组装centerPane
        centerPane.add(jspTemp,FlowLayout.LEFT);
        centerPane.add(point,FlowLayout.CENTER);
        centerPane.add(jspTemp2,FlowLayout.RIGHT);




        //底部显示面板，请求响应日志
        requestViewer = BurpExtender.callbacks.createMessageEditor(this, false);
        responseViewer = BurpExtender.callbacks.createMessageEditor(this, false);


        bottomTabs = new JTabbedPane();
        bottomTabs.addTab("Request", requestViewer.getComponent());
        bottomTabs.addTab("Response", responseViewer.getComponent());


        /***************************************payload面板******************************************/
        //payload面板
        payloadPane = new JPanel();
        payloadPane.setBorder(new EmptyBorder(5, 5, 40, 5));
        payloadPane.setLayout(new BorderLayout(0, 0));
        //分割为上下2块面板
        JSplitPane jspPayload = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        jspPayload.setDividerLocation(0.5);  //设置分割线位置
        payloadPane.add(jspPayload,BorderLayout.CENTER);

        //sql payload面板
        JPanel jPP_top = new JPanel();
        jPP_top.setBorder(new EmptyBorder(20, 5, 20, 5));
        jPP_top.setLayout(new BorderLayout(0, 0));

        //sql payload文本框
        JTextArea jta_sql = new JTextArea("%df' and sleep(3)%23\n'and '1'='1",10,16);
        jta_sql.setForeground(Color.BLACK);    //设置组件的背景色
        jta_sql.setFont(new Font("Courier",Font.PLAIN,18));    //修改字体样式
        jta_sql.setBackground(Color.LIGHT_GRAY);    //设置背景色
        JScrollPane jsp_sql = new JScrollPane(jta_sql);  //滑动框
        jsp_sql.setBorder(new EmptyBorder(0,5,0,20));
        JLabel lbSql = new JLabel("SQL payload");
        lbSql.setBorder(new EmptyBorder(0, 5, 0, 20));
        jPP_top.add(lbSql,BorderLayout.WEST);
        jPP_top.add(jsp_sql,BorderLayout.CENTER);

        //xss payload面板
        JPanel jPP_bottom = new JPanel();
        jPP_bottom.setBorder(new EmptyBorder(20, 5, 20, 5));
        jPP_bottom.setLayout(new BorderLayout(0, 0));

        //xss payload文本框
        JTextArea jta_xss = new JTextArea("<img>",10,16);
        jta_xss.setForeground(Color.BLACK);    //设置组件的背景色
        jta_xss.setFont(new Font("Courier",Font.PLAIN,18));    //修改字体样式
        jta_xss.setBackground(Color.LIGHT_GRAY);    //设置背景色
        JScrollPane jsp_xss = new JScrollPane(jta_xss); //滑动框
        jsp_xss.setBorder(new EmptyBorder(0,5,0,20));
        JLabel lbXss = new JLabel("XSS payload");
        lbXss.setBorder(new EmptyBorder(0, 5, 0, 20));
        jPP_bottom.add(lbXss,BorderLayout.WEST);
        jPP_bottom.add(jsp_xss,BorderLayout.CENTER);



        /*******************************************************顶部面板，配置各种按钮******************************************************/
        JPanel topPanel = new JPanel();
        GridBagLayout gridBagLayout = new GridBagLayout();
        topPanel.setLayout(gridBagLayout);

        //过滤域名
        lbDomain = new JLabel("Domain:");
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.BOTH;
        constraints.insets = new Insets(5, 5, 5, 5);
        constraints.gridx = 0;
        topPanel.add(lbDomain, constraints);

        tfDomain = new JTextField();
        tfDomain.setColumns(10);
        tfDomain.setText("");
        constraints.gridx = 1;
        topPanel.add(tfDomain, constraints);

        //过滤静态文件
        lbExcludeSuffix = new JLabel("ExcludeSuffix:");
        constraints.gridx = 2;
        topPanel.add(lbExcludeSuffix, constraints);

        tfExcludeSuffix = new JTextField();
        tfExcludeSuffix.setColumns(30);
        tfExcludeSuffix.setText("js|css|jpeg|gif|jpg|png|pdf|rar|zip|docx|doc|svg|jpeg|ico|woff|woff2|ttf|otf");
        constraints.gridx = 3;
        topPanel.add(tfExcludeSuffix, constraints);

        //sql检查按钮
        btnSql = new JToggleButton("SQL Check");
        btnSql.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent arg0) {
                boolean isSelected = btnSql.isSelected();

                if(isSelected){
                    btnSql.setText("Stop SQL");
                    Config.sqlCheck_isRunning = true;
                    Config.DOMAIN_REGX = tfDomain.getText();
                    Config.SUFFIX_REGX = tfExcludeSuffix.getText();
                    setAllEnabled(false);
                }else{
                    btnSql.setText("SQL Check");
                    Config.sqlCheck_isRunning = false;
                    setAllEnabled(true);
                }
                btnSql.setSelected(isSelected);
            }
        });
        constraints.gridx = 4;
        topPanel.add(btnSql, constraints);

        //Xss检查按钮
        btnXss = new JToggleButton("XSS Check");
        btnXss.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent arg0) {
                boolean isSelected = btnXss.isSelected();

                if(isSelected){
                    btnXss.setText("Stop XSS");
                    Config.xssCheck_isRunning = true;
                }else{
                    btnXss.setText("XSS Check");
                    Config.xssCheck_isRunning = false;
                }
                btnXss.setSelected(isSelected);
            }
        });
        constraints.gridx = 5;
        topPanel.add(btnXss, constraints);

        //加载自定义payload按钮
        //Xss检查按钮
        btnPayload = new JToggleButton("Load Payload");
        btnPayload.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent arg0) {
                boolean isSelected = btnPayload.isSelected();

                if(isSelected){
                    btnPayload.setText("Stop Payload");
                    Config.loadPayload_isRunning = true;
                    Config.SQLPAYLOAD = jta_sql.getText().split("\n");
                    Config.XSSPAYLOAD = jta_xss.getText().split("\n");
                }else{
                    btnPayload.setText("Load Payload");
                    Config.loadPayload_isRunning = false;
                }
                btnPayload.setSelected(isSelected);
            }
        });
        constraints.gridx = 6;
        topPanel.add(btnPayload, constraints);

        //清除按钮
        JButton clear = new JButton("Clear");
        clear.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int n = JOptionPane.showConfirmDialog(null, "Are you sure you want to clear the data？", "LazyQS", JOptionPane.YES_NO_OPTION);
                if(n == 0) {
                    BurpExtender.httpLog.clear();
                    BurpExtender.paraLog.clear();
                    BurpExtender.detailLog.clear();
                    httpLogTable.getHttpLogTableModel().fireTableDataChanged();//通知模型更新
                    httpLogTable.updateUI();//刷新表格
                    paraLogTable.getParaLogTableModel().fireTableDataChanged();
                    paraLogTable.updateUI();
                    requestViewer.setMessage("".getBytes(),true);
                    responseViewer.setMessage("".getBytes(),false);
                }
            }
        });
        constraints.gridx = 7;
        topPanel.add(clear,constraints);





        /****************************************开始组装*********************************************/
        //组装check视图
        contentPane.add(topPanel,BorderLayout.NORTH);
        contentPane.add(this.jSplitPane,BorderLayout.CENTER);
        this.jSplitPane.setTopComponent(centerPane);
        this.jSplitPane.setBottomComponent(bottomTabs);
        jSplitPane.setDividerLocation(0.5);  //设置分割线位置


        //组装payload视图
        jspPayload.setTopComponent(jPP_top);
        jspPayload.setBottomComponent(jPP_bottom);

        //添加两个主面板到选项卡
        tabs.addTab("check",contentPane);
        tabs.addTab("payload",payloadPane);

        BurpExtender.callbacks.customizeUiComponent(contentPane);
        BurpExtender.callbacks.customizeUiComponent(centerPane);
        BurpExtender.callbacks.customizeUiComponent(bottomTabs);
        BurpExtender.callbacks.customizeUiComponent(jSplitPane);
        BurpExtender.callbacks.customizeUiComponent(payloadPane);
        BurpExtender.callbacks.customizeUiComponent(tabs);

        return tabs;
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    //设置点按sql开关时，其他输入框变灰
    public void setAllEnabled(boolean is){
        tfDomain.setEnabled(is);
        tfExcludeSuffix.setEnabled(is);
    }
}
