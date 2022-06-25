package burp;

import javax.swing.table.AbstractTableModel;

public class ParaLogTableModel extends AbstractTableModel {
    @Override
    public int getRowCount() {
        return BurpExtender.detailLog.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex){
            case 0:
                return "Parameter";
            case 1:
                return "Payload";
            case 2:
                return "Length";
            case 3:
                return "Vulnerable";
            case 4:
                return "Time";
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
        LogEntry logEntry = BurpExtender.detailLog.get(rowIndex);
        switch (columnIndex){
            case 0:
                return logEntry.parameter;
            case 1:
                return logEntry.payload;
            case 2:
                return logEntry.requestResponse.getResponse().length;
            case 3:
                return logEntry.vulnerable;
            case 4:
                return logEntry.times;
            default:
                return "";
        }
    }
}
