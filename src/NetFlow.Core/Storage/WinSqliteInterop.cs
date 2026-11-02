using System.Runtime.InteropServices;
using System.Text;

namespace NetFlow.Core.Storage;

public static class WinSqliteInterop
{
    private const string LibName = "winsqlite3.dll";

    public const int SQLITE_OK = 0;
    public const int SQLITE_ROW = 100;
    public const int SQLITE_DONE = 101;

    public const int SQLITE_OPEN_READWRITE = 0x00000002;
    public const int SQLITE_OPEN_CREATE = 0x00000004;

    public static readonly IntPtr SQLITE_STATIC = IntPtr.Zero;
    public static readonly IntPtr SQLITE_TRANSIENT = new IntPtr(-1);

    [DllImport(LibName, EntryPoint = "sqlite3_open_v2", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Open(byte[] filename, out IntPtr ppDb, int flags, IntPtr zVfs);

    [DllImport(LibName, EntryPoint = "sqlite3_close_v2", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Close(IntPtr db);

    [DllImport(LibName, EntryPoint = "sqlite3_exec", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Exec(IntPtr db, byte[] sql, IntPtr callback, IntPtr arg, out IntPtr errmsg);

    [DllImport(LibName, EntryPoint = "sqlite3_prepare_v2", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Prepare(IntPtr db, byte[] zSql, int nByte, out IntPtr ppStmt, IntPtr pzTail);

    [DllImport(LibName, EntryPoint = "sqlite3_step", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Step(IntPtr stmt);

    [DllImport(LibName, EntryPoint = "sqlite3_finalize", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Finalize(IntPtr stmt);

    [DllImport(LibName, EntryPoint = "sqlite3_reset", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Reset(IntPtr stmt);

    [DllImport(LibName, EntryPoint = "sqlite3_clear_bindings", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ClearBindings(IntPtr stmt);

    [DllImport(LibName, EntryPoint = "sqlite3_bind_int", CallingConvention = CallingConvention.Cdecl)]
    public static extern int BindInt(IntPtr stmt, int index, int value);

    [DllImport(LibName, EntryPoint = "sqlite3_bind_int64", CallingConvention = CallingConvention.Cdecl)]
    public static extern int BindInt64(IntPtr stmt, int index, long value);

    [DllImport(LibName, EntryPoint = "sqlite3_bind_double", CallingConvention = CallingConvention.Cdecl)]
    public static extern int BindDouble(IntPtr stmt, int index, double value);

    [DllImport(LibName, EntryPoint = "sqlite3_bind_text", CallingConvention = CallingConvention.Cdecl)]
    public static extern int BindText(IntPtr stmt, int index, byte[] text, int len, IntPtr destructor);

    [DllImport(LibName, EntryPoint = "sqlite3_bind_null", CallingConvention = CallingConvention.Cdecl)]
    public static extern int BindNull(IntPtr stmt, int index);

    [DllImport(LibName, EntryPoint = "sqlite3_column_count", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ColumnCount(IntPtr stmt);

    [DllImport(LibName, EntryPoint = "sqlite3_column_name", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ColumnName(IntPtr stmt, int col);

    [DllImport(LibName, EntryPoint = "sqlite3_column_int", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ColumnInt(IntPtr stmt, int col);

    [DllImport(LibName, EntryPoint = "sqlite3_column_int64", CallingConvention = CallingConvention.Cdecl)]
    public static extern long ColumnInt64(IntPtr stmt, int col);

    [DllImport(LibName, EntryPoint = "sqlite3_column_double", CallingConvention = CallingConvention.Cdecl)]
    public static extern double ColumnDouble(IntPtr stmt, int col);

    [DllImport(LibName, EntryPoint = "sqlite3_column_text", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ColumnText(IntPtr stmt, int col);

    [DllImport(LibName, EntryPoint = "sqlite3_column_type", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ColumnType(IntPtr stmt, int col);

    [DllImport(LibName, EntryPoint = "sqlite3_errmsg", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ErrMsg(IntPtr db);

    [DllImport(LibName, EntryPoint = "sqlite3_changes", CallingConvention = CallingConvention.Cdecl)]
    public static extern int Changes(IntPtr db);

    public static byte[] Utf8Bytes(string s) => Encoding.UTF8.GetBytes(s + "\0");

    public static string PtrToStringUtf8(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero) return "";
        int len = 0;
        while (Marshal.ReadByte(ptr, len) != 0) len++;
        byte[] buffer = new byte[len];
        Marshal.Copy(ptr, buffer, 0, len);
        return Encoding.UTF8.GetString(buffer);
    }
}
