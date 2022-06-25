package burp;

import javax.swing.*;
import javax.swing.table.TableModel;

public class ParaLogTable extends JTable {
    private ParaLogTableModel paraLogTableModel;

    public ParaLogTableModel getParaLogTableModel(){
        return paraLogTableModel;
    }
    public ParaLogTable(TableModel tableModel){
        super(tableModel);
        this.paraLogTableModel = (ParaLogTableModel) tableModel;
    }

    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        //设置点按参数日志时，底部显示详细日志的内容
        LogEntry logEntry = BurpExtender.detailLog.get(rowIndex);
        GUI.requestViewer.setMessage(logEntry.requestResponse.getRequest(),true);
        GUI.responseViewer.setMessage(logEntry.requestResponse.getResponse(),false);
        GUI.currentlyDisplayedItem = logEntry.requestResponse;
        super.changeSelection(rowIndex, columnIndex, toggle, extend);
    }
}
