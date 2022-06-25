package burp;

public class Config {
    public static boolean sqlCheck_isRunning = false;
    public static boolean xssCheck_isRunning = false;
    public static boolean loadPayload_isRunning = false;

    public static String DOMAIN_REGX = "";
    public static String SUFFIX_REGX = "js|css|jpeg|gif|jpg|png|pdf|rar|zip|docx|doc|svg|jpeg|ico|woff|woff2|ttf|otf";

    public static String[] SQLPAYLOAD = {};
    public static String[] XSSPAYLOAD = {};

    public static String[] SQL = new String[]{
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "SQL syntax",
            "Warning: mysql_",
            "Warning: pg_",
            "Warning: mssql_",
            "Warning: sqlsrv_",
            "Warning: oci_",
            "Warning: ora_",
            "syntax error at or near",
            "Unknown column",
            "check the manual that corresponds",
            "com.mysql.jdbc",
            "Syntax error or access violation",
            "MySqlClient.",
            "Mysqli_Exception",
            "MySqlException",
            "MemSQL does not support this type of query",
            "is not supported by MemSQL",
            "unsupported nested scalar subselect",
            "valid PostgreSQL result",
            "Npgsql.",
            "PG::SyntaxError:",
            "org.postgresql.util.PSQLException",
            "ERROR: parser: parse error at or near",
            "PostgreSQL query failed",
            "org.postgresql.jdbc",
            "PSQLException",
            "System.Data.SqlClient",
            "Microsoft SQL Native Client error",
            "[SQL Server]",
            "ODBC SQL Server Driver",
            "SQLServer JDBC Driver",
            "com.jnetdirect.jsql",
            "macromedia.jdbc.sqlserver",
            "Sqlsrv_Exception",
            "com.microsoft.sqlserver.jdbc",
            "SQLSrvException",
            "SQLServerException",
            "Unclosed quotation mark after the character string",
            "Oracle error",
            "quoted string not properly terminated",
            "SQL command not properly ended",
            "macromedia.jdbc.oracle",
            "oracle.jdbc",
            "Oracle.jdbc",
            "Zend_Db_",
            "Oracle_Exception",
            "OracleException",
            "ORA-",
            "ODBC Driver",
            "PDOStatement",
            "SQLSTATE["
    };

    //上面列表匹配不了的部分正则
    public static String[] SQL_REGX = new String[]{
            "Warning.*?\\Wmysqli?_",
            "Pdo[./_\\\\]Mysql",
            "PostgreSQL.*?ERROR",
            "Warning.*?\\Wpg_",
            "Pdo[./_\\\\]Pgsql",
            "Driver.*? SQL[\\-\\_\\ ]*Server",
            "OLE DB.*? SQL Server",
            "\\bSQL Server[^&lt;&quot;]+Driver",
            "Warning.*?\\W(mssql|sqlsrv)_",
            "\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
            "(?s)Exception.*?\\bRoadhouse\\.Cms\\.",
            "Pdo[./_\\\\](Mssql|SqlSrv)",
            "Oracle.*?Driver",
            "Warning.*?\\W(oci|ora)_",
            "Pdo[./_\\\\](Oracle|OCI)"
            };

}
