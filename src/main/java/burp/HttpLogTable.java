package burp;

import javax.swing.*;
import javax.swing.table.TableModel;

public class HttpLogTable extends JTable {
    private final HttpLogTableModel httpLogTableModel;
    private int sign;

    public HttpLogTableModel getHttpLogTableModel(){
        return httpLogTableModel;
    }
    public HttpLogTable(TableModel tableModel){
        super(tableModel);
        this.httpLogTableModel = (HttpLogTableModel) tableModel;
    }

    public int getSign() {
        return sign;
    }

    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        LogEntry logEntry = BurpExtender.httpLog.get(rowIndex);
        sign = logEntry.id;
        //用来存储同一个请求里的参数日志，当选择的http请求日志变更，就要清空这个容器，从新填充当前选中的请求参数日志
        BurpExtender.detailLog.clear();
        //通过比对日志的id值，确定哪些参数的日志是同一个请求日志里的
        for (int i=0;i < BurpExtender.paraLog.size();i++){
            if (BurpExtender.paraLog.get(i).id == sign){
                BurpExtender.detailLog.add(BurpExtender.paraLog.get(i));
            }
        }

        //刷新第二个表格页面行数
        GUI.paraLogTable.getParaLogTableModel().fireTableRowsInserted(BurpExtender.detailLog.size(),BurpExtender.detailLog.size());
        //刷新第二个表格页面数据
        GUI.paraLogTable.getParaLogTableModel().fireTableDataChanged();

        //设置底部详细日志的显示
        GUI.requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
        GUI.responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
        GUI.currentlyDisplayedItem = logEntry.requestResponse;

        super.changeSelection(rowIndex, columnIndex, toggle, extend);
    }
}
