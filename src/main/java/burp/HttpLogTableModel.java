package burp;

import javax.swing.table.AbstractTableModel;

public class HttpLogTableModel extends AbstractTableModel {
    @Override
    public int getRowCount() {
        return BurpExtender.httpLog.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex){
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Length";
            case 4:
                return "Status";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = BurpExtender.httpLog.get(rowIndex);
        switch (columnIndex){
            case 0:
                return logEntry.id;
            case 1:
                return logEntry.method;
            case 2:
                return logEntry.url.toString();
            case 3:
                return logEntry.requestResponse.getResponse().length;
            case 4:
                return logEntry.state;
            default:
                return "";
        }
    }
}
