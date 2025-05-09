using System;
using System.Runtime.InteropServices;

namespace Npam.Interop
{
    public class Pam {
        [DllImport("libpam")]
        public static extern PamStatus pam_start([MarshalAs(UnmanagedType.LPStr)] string serviceName, [MarshalAs(UnmanagedType.LPStr)] string user, PamConv conversation, ref IntPtr pamHandle);
        [DllImport("libpam")]
        public static extern PamStatus pam_authenticate(IntPtr pamHandle, int flags);
        [DllImport("libpam")]
        public static extern PamStatus pam_acct_mgmt(IntPtr pamHandle, int flags);
        [DllImport("libpam")]
        public static extern PamStatus pam_end(IntPtr pamHandle, PamStatus pamStatus);
        [DllImport("libpam")]
        public static extern PamStatus pam_chauthtok(IntPtr pamHandle, int flags);
    }
}