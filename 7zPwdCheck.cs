// ============================================================================
//  7zPwdCheck.cs —— 7z 密码批量验证器
//
//  用途: 把多个加密压缩包拖进窗口,输入一个密码,回车,
//        即可批量检查这个密码对每个压缩包是否正确。
//        (专为「7z 加密备份」工具生成的包优化:文件名加密的包
//         瞬间出结果;也支持其他 7z/zip 包,会自动做完整校验)
//
//  编译: 双击 build_pwdcheck.bat(用 Windows 自带编译器,无需装任何东西)
//  自检: 7zPwdCheck.exe --selftest   结果写入 7zPwdCheck_result.txt
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace SevenZipPwdCheck
{
    internal static class Program
    {
        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();

        [STAThread]
        private static void Main(string[] args)
        {
            if (args != null && args.Length > 0 && (args[0] == "--selftest" || args[0] == "/selftest"))
            {
                SelfTest.RunAll();
                return;
            }
            try { SetProcessDPIAware(); } catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    // -------------------------------------------------------------- 7z 定位
    internal static class SevenZipLocator
    {
        public static string Find()
        {
            string[] dirs = new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetEnvironmentVariable("ProgramW6432"),
                Environment.GetEnvironmentVariable("ProgramFiles(x86)")
            };
            foreach (string d in dirs)
            {
                if (string.IsNullOrEmpty(d)) continue;
                string p = Path.Combine(d, "7-Zip\\7z.exe");
                if (File.Exists(p)) return p;
            }
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey("SOFTWARE\\7-Zip"))
                {
                    if (k != null)
                    {
                        object v = k.GetValue("Path");
                        if (v != null)
                        {
                            string p = Path.Combine(v.ToString(), "7z.exe");
                            if (File.Exists(p)) return p;
                        }
                    }
                }
            }
            catch { }
            string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in pathEnv.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    string p = Path.Combine(dir.Trim().Trim('"'), "7z.exe");
                    if (File.Exists(p)) return p;
                }
                catch { }
            }
            return null;
        }
    }

    // ------------------------------------------------------------- 7z 执行器
    internal class RunResult
    {
        public int ExitCode;
        public string Output = "";
        public string Error = "";
    }

    internal class SevenZipRunner
    {
        public string SevenZipPath;
        public volatile bool CancelRequested;
        private Process _proc;
        private readonly object _lock = new object();

        public RunResult Run(string[] args, Action<int> onProgress)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = SevenZipPath;
            psi.Arguments = JoinArgs(args);
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;

            var sbOut = new StringBuilder();
            var sbErr = new StringBuilder();
            using (Process p = Process.Start(psi))
            {
                lock (_lock)
                {
                    _proc = p;
                    if (CancelRequested) { try { p.Kill(); } catch { } }
                }
                Thread errThread = new Thread(delegate()
                {
                    try { string e; while ((e = p.StandardError.ReadLine()) != null) { lock (sbErr) sbErr.AppendLine(e); } }
                    catch { }
                });
                errThread.IsBackground = true;
                errThread.Start();

                Regex pct = new Regex("^\\s*(\\d{1,3})%");
                string line;
                while ((line = p.StandardOutput.ReadLine()) != null)
                {
                    lock (sbOut) sbOut.AppendLine(line);
                    if (onProgress != null)
                    {
                        Match m = pct.Match(line);
                        int v;
                        if (m.Success && int.TryParse(m.Groups[1].Value, out v)) onProgress(v);
                    }
                }
                p.WaitForExit();
                lock (_lock) _proc = null;
                RunResult r = new RunResult();
                r.ExitCode = p.ExitCode;
                lock (sbOut) r.Output = sbOut.ToString();
                lock (sbErr) r.Error = sbErr.ToString();
                return r;
            }
        }

        public void Cancel()
        {
            CancelRequested = true;
            Process p;
            lock (_lock) p = _proc;
            if (p != null) { try { p.Kill(); } catch { } }
        }

        public static string JoinArgs(string[] args)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < args.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append('"').Append(args[i]).Append('"');
            }
            return sb.ToString();
        }
    }

    // ------------------------------------------------------------ 验证核心
    internal enum CheckResult { Ok, WrongPassword, NotEncrypted, Error, Cancelled }

    internal class CheckOutcome
    {
        public CheckResult Result;
        public string Message = "";
    }

    internal static class CheckCore
    {
        // 探测密码用的"冒充密码":用于判断压缩包的文件名是否加密。
        // (文件名加密的包,用冒充密码连目录都列不出来;未加密的则列得出来)
        private const string ProbePwd = "ZqProbe_7b8c9d0e1f_NOT_A_REAL_PASSWORD";

        // deep=false: 只验证密码(文件名加密的包瞬间完成)
        // deep=true : 验证密码 + 完整解密核对每个文件(慢,但确认备份可用)
        public static CheckOutcome Check(SevenZipRunner runner, string archive, string pwd, bool deep,
                                         Action<int> onItemProgress)
        {
            // 第一步: 用用户密码尝试列出目录
            RunResult r = runner.Run(new[] { "l", "-slt", "-sccUTF-8", "-p" + pwd, "--", archive }, null);
            if (runner.CancelRequested) return Cancelled();
            if (r.ExitCode != 0)
            {
                string all = (r.Output ?? "") + "\r\n" + (r.Error ?? "");
                if (IsWrongPassword(all))
                    return new CheckOutcome { Result = CheckResult.WrongPassword, Message = "密码错误" };
                return new CheckOutcome
                {
                    Result = CheckResult.Error,
                    Message = "无法打开: " + Tail(all.Trim(), 300)
                };
            }

            // 列目录成功。看看包里有没有加密内容。
            string out1 = r.Output ?? "";
            if (out1.IndexOf("Encrypted = +", StringComparison.Ordinal) < 0)
                return new CheckOutcome { Result = CheckResult.NotEncrypted, Message = "该压缩包没有加密(任何密码都能打开)" };

            // 有加密内容。用冒充密码再列一次,判断文件名是否加密:
            RunResult rp = runner.Run(new[] { "l", "-slt", "-sccUTF-8", "-p" + ProbePwd, "--", archive }, null);
            if (runner.CancelRequested) return Cancelled();
            if (rp.ExitCode != 0)
            {
                // 冒充密码失败 => 文件名已加密 => 刚才用户密码能列出目录,说明密码正确
                return deep ? DeepTest(runner, archive, pwd, onItemProgress)
                            : new CheckOutcome { Result = CheckResult.Ok, Message = "密码正确" };
            }

            // 文件名未加密(比如普通 zip 或未开 -mhe 的 7z):
            // 列目录成功不能说明密码对,必须做完整解密测试。
            return DeepTest(runner, archive, pwd, onItemProgress);
        }

        private static CheckOutcome DeepTest(SevenZipRunner runner, string archive, string pwd, Action<int> onItemProgress)
        {
            RunResult t = runner.Run(new[] { "t", "-sccUTF-8", "-p" + pwd, "--", archive }, onItemProgress);
            if (runner.CancelRequested) return Cancelled();
            if (t.ExitCode == 0)
                return new CheckOutcome { Result = CheckResult.Ok, Message = "密码正确(已完整解密核对)" };
            string all = (t.Output ?? "") + "\r\n" + (t.Error ?? "");
            if (IsWrongPassword(all))
                return new CheckOutcome { Result = CheckResult.WrongPassword, Message = "密码错误" };
            return new CheckOutcome
            {
                Result = CheckResult.Error,
                Message = "密码可能正确,但数据核对失败: " + Tail(all.Trim(), 300)
            };
        }

        private static bool IsWrongPassword(string s)
        {
            return s.IndexOf("Wrong password", StringComparison.OrdinalIgnoreCase) >= 0
                || (s.IndexOf("Cannot open", StringComparison.OrdinalIgnoreCase) >= 0
                    && s.IndexOf("encrypted", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static CheckOutcome Cancelled()
        {
            return new CheckOutcome { Result = CheckResult.Cancelled, Message = "已取消" };
        }

        public static string Tail(string s, int n)
        {
            if (string.IsNullOrEmpty(s) || s.Length <= n) return s;
            return "……" + s.Substring(s.Length - n);
        }
    }

    // ------------------------------------------------------------------ 自检
    internal static class SelfTest
    {
        public static void RunAll()
        {
            var log = new StringBuilder();
            log.AppendLine("7z密码验证器 自检报告  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            string z = SevenZipLocator.Find();
            log.AppendLine("7z 路径: " + (z ?? "(未找到)"));
            string baseDir = Path.Combine(Path.GetTempPath(),
                "7zPwdCheckTest_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            int fail = 0;
            try
            {
                Action<string, bool> check = delegate(string name, bool ok)
                {
                    log.AppendLine((ok ? "[PASS] " : "[FAIL] ") + name);
                    if (!ok) fail++;
                };

                Directory.CreateDirectory(baseDir);
                string src = Path.Combine(baseDir, "数据");
                Directory.CreateDirectory(src);
                File.WriteAllText(Path.Combine(src, "测试文件.txt"),
                    "内容123ABC\r\n", Encoding.UTF8);

                string pwdA = "正确密码甲123";
                string pwdB = "另一个密码乙456";
                var runner = new SevenZipRunner { SevenZipPath = z };
                check("找到 7z.exe", z != null);
                if (z == null) throw new Exception("未找到 7z.exe");

                // A: 文件名加密 + 密码A (与主工具相同的方式)
                string A = Path.Combine(baseDir, "包A.7z");
                MustZero(runner.Run(new[] { "a", "-t7z", "-mhe=on", "-p" + pwdA, "--", A, src }, null), "压缩A");
                // B: 文件名加密 + 密码B
                string B = Path.Combine(baseDir, "包B.7z");
                MustZero(runner.Run(new[] { "a", "-t7z", "-mhe=on", "-p" + pwdB, "--", B, src }, null), "压缩B");
                // C: 不加密
                string C = Path.Combine(baseDir, "包C.7z");
                MustZero(runner.Run(new[] { "a", "-t7z", "--", C, src }, null), "压缩C");
                // D: 分卷 + 文件名加密 + 密码A
                string D = Path.Combine(baseDir, "包D.7z");
                MustZero(runner.Run(new[] { "a", "-t7z", "-mhe=on", "-p" + pwdA, "-v10k", "--", D, src }, null), "压缩D");
                // E: 只加密内容、不加密文件名 + 密码A
                string E = Path.Combine(baseDir, "包E.7z");
                MustZero(runner.Run(new[] { "a", "-t7z", "-p" + pwdA, "--", E, src }, null), "压缩E");

                check("快速:正确密码(文件名加密包A)", CheckCore.Check(runner, A, pwdA, false, null).Result == CheckResult.Ok);
                check("快速:错误密码(包A)", CheckCore.Check(runner, A, "猜错的密码000", false, null).Result == CheckResult.WrongPassword);
                check("快速:拿A的密码去开B → 密码错误", CheckCore.Check(runner, B, pwdA, false, null).Result == CheckResult.WrongPassword);
                check("快速:B用自己的密码 → 正确", CheckCore.Check(runner, B, pwdB, false, null).Result == CheckResult.Ok);
                check("快速:未加密包C → 提示未加密", CheckCore.Check(runner, C, "随便什么", false, null).Result == CheckResult.NotEncrypted);
                check("快速:分卷包D(.001)正确密码", CheckCore.Check(runner, D + ".001", pwdA, false, null).Result == CheckResult.Ok);
                check("快速:分卷包D(.001)错误密码", CheckCore.Check(runner, D + ".001", "错的", false, null).Result == CheckResult.WrongPassword);
                check("快速:文件名未加密包E+正确密码(自动升级完整校验)",
                    CheckCore.Check(runner, E, pwdA, false, null).Result == CheckResult.Ok);
                check("快速:文件名未加密包E+错误密码(自动升级完整校验)",
                    CheckCore.Check(runner, E, "错的", false, null).Result == CheckResult.WrongPassword);
                check("深度:包A正确密码(完整解密核对)", CheckCore.Check(runner, A, pwdA, true, null).Result == CheckResult.Ok);
                check("深度:包A错误密码", CheckCore.Check(runner, A, "错的", true, null).Result == CheckResult.WrongPassword);
            }
            catch (Exception ex)
            {
                log.AppendLine("[EXCEPTION] " + ex.ToString());
                fail++;
            }
            log.AppendLine();
            log.AppendLine(fail == 0 ? "结果: 全部通过" : ("结果: " + fail + " 项失败"));

            string logPath;
            try { logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "7zPwdCheck_result.txt"); }
            catch { logPath = Path.Combine(Path.GetTempPath(), "7zPwdCheck_result.txt"); }
            try { File.WriteAllText(logPath, log.ToString(), Encoding.UTF8); } catch { }
        }

        private static void MustZero(RunResult r, string what)
        {
            if (r.ExitCode != 0)
                throw new Exception(what + " 失败: " + CheckCore.Tail((r.Output ?? "") + r.Error, 300));
        }
    }

    // ------------------------------------------------------------------ 主窗口
    internal class MainForm : Form
    {
        private string _7zPath;
        private Panel _dropPanel;
        private Label _dropLabel, _lblStatus;
        private ListView _list;
        private TextBox _txtPwd;
        private CheckBox _chkShow, _chkDeep;
        private Button _btnStart, _btnCancel, _btnClear;
        private ProgressBar _bar;

        private readonly List<string> _items = new List<string>();
        private SevenZipRunner _runner;
        private Thread _worker;

        public MainForm()
        {
            _7zPath = SevenZipLocator.Find();
            BuildUi();
            if (_7zPath == null)
            {
                _lblStatus.ForeColor = Color.Firebrick;
                _lblStatus.Text = "未找到 7-Zip。请先安装 7-Zip(www.7-zip.org)后重试。";
                MessageBox.Show(this, "没有找到 7-Zip 的 7z.exe。\r\n请先安装 7-Zip(默认安装即可),再重新打开本程序。",
                    "7z 密码验证", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void BuildUi()
        {
            Text = "7z 密码验证 —— 批量检查压缩包密码";
            Font = new Font("Microsoft YaHei UI", 9F);
            ClientSize = new Size(640, 470);
            MinimumSize = new Size(600, 440);
            StartPosition = FormStartPosition.CenterScreen;

            _dropPanel = new Panel();
            _dropPanel.Location = new Point(12, 12);
            _dropPanel.Size = new Size(616, 78);
            _dropPanel.BorderStyle = BorderStyle.FixedSingle;
            _dropPanel.BackColor = Color.FromArgb(245, 248, 252);
            _dropPanel.Cursor = Cursors.Hand;
            _dropLabel = new Label();
            _dropLabel.Dock = DockStyle.Fill;
            _dropLabel.TextAlign = ContentAlignment.MiddleCenter;
            _dropLabel.Text = "把加密压缩包(.7z,可多个)拖到这里\r\n也可以拖入文件夹(自动找出里面的压缩包)";
            _dropLabel.ForeColor = Color.FromArgb(70, 90, 120);
            _dropPanel.Controls.Add(_dropLabel);
            Controls.Add(_dropPanel);
            EnableDrop(_dropPanel);
            EnableDrop(_dropLabel);
            _dropPanel.Click += delegate { AddFilesDialog(); };
            _dropLabel.Click += delegate { AddFilesDialog(); };

            _btnClear = MkBtn("清空列表", 12, 98, 96);
            _btnClear.Click += delegate { ClearAll(); };

            _list = new ListView();
            _list.Location = new Point(12, 130);
            _list.Size = new Size(616, 168);
            _list.View = View.Details;
            _list.FullRowSelect = true;
            _list.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            _list.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            _list.Columns.Add("压缩包", 430);
            _list.Columns.Add("结果", 176);
            _list.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Delete) { RemoveSelected(); e.Handled = true; }
            };
            Controls.Add(_list);
            EnableDrop(_list);

            Label lblPwd = new Label();
            lblPwd.Text = "密码:";
            lblPwd.Location = new Point(12, 310);
            lblPwd.Size = new Size(48, 23);
            Controls.Add(lblPwd);
            _txtPwd = new TextBox();
            _txtPwd.Location = new Point(64, 307);
            _txtPwd.Width = 420;
            _txtPwd.PasswordChar = '\u25CF';
            _txtPwd.MaxLength = 128;
            _txtPwd.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _txtPwd.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; e.Handled = true; DoStart(); }
            };
            Controls.Add(_txtPwd);
            _chkShow = new CheckBox();
            _chkShow.Text = "显示密码";
            _chkShow.AutoSize = true;
            _chkShow.Location = new Point(500, 309);
            _chkShow.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _chkShow.CheckedChanged += delegate { _txtPwd.PasswordChar = _chkShow.Checked ? '\0' : '\u25CF'; };
            Controls.Add(_chkShow);

            _chkDeep = new CheckBox();
            _chkDeep.Text = "完整校验(解密全部数据并核对完整性,较慢;不勾选则只验证密码)";
            _chkDeep.AutoSize = true;
            _chkDeep.Location = new Point(12, 340);
            Controls.Add(_chkDeep);

            _btnStart = MkBtn("开始验证", 12, 370, 150, 38);
            _btnStart.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold);
            _btnStart.BackColor = Color.FromArgb(36, 110, 220);
            _btnStart.ForeColor = Color.White;
            _btnStart.FlatStyle = FlatStyle.System;
            _btnStart.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            _btnStart.Click += delegate { DoStart(); };
            Controls.Add(_btnStart);

            _btnCancel = MkBtn("取消", 172, 370, 90, 38);
            _btnCancel.Enabled = false;
            _btnCancel.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            _btnCancel.Click += delegate
            {
                if (_runner != null) _runner.Cancel();
                _lblStatus.Text = "正在取消…";
            };
            Controls.Add(_btnCancel);

            _bar = new ProgressBar();
            _bar.Location = new Point(12, 418);
            _bar.Size = new Size(616, 18);
            _bar.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(_bar);

            _lblStatus = new Label();
            _lblStatus.Location = new Point(12, 442);
            _lblStatus.Size = new Size(616, 24);
            _lblStatus.ForeColor = Color.DimGray;
            _lblStatus.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            _lblStatus.Text = "拖入压缩包 → 输入密码 → 回车。密码不会保存。";
            Controls.Add(_lblStatus);

            EnableDrop(this);
            ScaleForDpi();
        }

        // ---- 手动 DPI 缩放 -------------------------------------------------
        // (与主程序相同的原因:AutoScaleMode 在部分环境不生效,这里手动缩放)
        private void ScaleForDpi()
        {
            float f = 1f;
            try { using (Graphics g = CreateGraphics()) f = g.DpiX / 96f; } catch { }
            if (f <= 1.01f) return;

            var saved = new List<KeyValuePair<Control, AnchorStyles>>();
            SaveAnchors(this, saved);
            SetAllAnchors(this, AnchorStyles.Top | AnchorStyles.Left);

            ScaleTree(this, f);
            foreach (ColumnHeader col in _list.Columns) col.Width = (int)(col.Width * f);
            ClientSize = new Size((int)(640 * f), (int)(470 * f));
            MinimumSize = new Size((int)(600 * f), (int)(440 * f));

            foreach (KeyValuePair<Control, AnchorStyles> kv in saved) kv.Key.Anchor = kv.Value;
        }

        private static void SaveAnchors(Control root, List<KeyValuePair<Control, AnchorStyles>> into)
        {
            foreach (Control c in root.Controls)
            {
                into.Add(new KeyValuePair<Control, AnchorStyles>(c, c.Anchor));
                SaveAnchors(c, into);
            }
        }

        private static void SetAllAnchors(Control root, AnchorStyles a)
        {
            foreach (Control c in root.Controls)
            {
                c.Anchor = a;
                SetAllAnchors(c, a);
            }
        }

        private static void ScaleTree(Control root, float f)
        {
            foreach (Control c in root.Controls)
            {
                c.Location = new Point(
                    (int)Math.Round(c.Location.X * f),
                    (int)Math.Round(c.Location.Y * f));
                if (!c.AutoSize)
                    c.Size = new Size(
                        (int)Math.Round(c.Size.Width * f),
                        (int)Math.Round(c.Size.Height * f));
                ScaleTree(c, f);
            }
        }

        private Button MkBtn(string text, int x, int y, int w)
        {
            Button b = new Button();
            b.Text = text;
            b.Location = new Point(x, y);
            b.Size = new Size(w, 26);
            Controls.Add(b);
            return b;
        }

        private Button MkBtn(string text, int x, int y, int w, int h)
        {
            Button b = MkBtn(text, x, y, w);
            b.Height = h;
            return b;
        }

        private void EnableDrop(Control c)
        {
            c.AllowDrop = true;
            c.DragEnter += delegate(object s, DragEventArgs e)
            {
                e.Effect = (e.Data != null && e.Data.GetDataPresent(DataFormats.FileDrop))
                    ? DragDropEffects.Copy : DragDropEffects.None;
            };
            c.DragDrop += delegate(object s, DragEventArgs e)
            {
                try
                {
                    string[] arr = e.Data.GetData(DataFormats.FileDrop) as string[];
                    if (arr != null && arr.Length > 0 && !IsBusy()) AddPaths(arr);
                }
                catch { }
            };
        }

        // ---------------------------------------------------------- 列表管理
        private void AddFilesDialog()
        {
            if (IsBusy()) return;
            using (var d = new OpenFileDialog())
            {
                d.Title = "选择压缩包(可多选)";
                d.Filter = "压缩包|*.7z;*.zip;*.001|所有文件|*.*";
                d.Multiselect = true;
                if (d.ShowDialog(this) == DialogResult.OK) AddPaths(d.FileNames);
            }
        }

        private void AddPaths(string[] paths)
        {
            var found = new List<string>();
            foreach (string raw in paths)
            {
                try
                {
                    string n = Path.GetFullPath(raw);
                    if (Directory.Exists(n)) CollectFromFolder(n, found);
                    else if (File.Exists(n) && !IsNonFirstVolume(n)) found.Add(n);
                }
                catch { }
            }
            foreach (string f in found)
                if (!_items.Contains(f)) _items.Add(f);
            RefreshList();
            if (found.Count > 0)
                _lblStatus.Text = "已添加 " + _items.Count + " 个压缩包。输入密码后按回车开始验证。";
        }

        private static bool IsNonFirstVolume(string file)
        {
            // 分卷 .002/.003… 不用单独验证(验证 .001 就够了)
            Match m = Regex.Match(Path.GetFileName(file), @"\.(\d{3})$", RegexOptions.IgnoreCase);
            return m.Success && int.Parse(m.Groups[1].Value) > 1;
        }

        private static void CollectFromFolder(string dir, List<string> into)
        {
            try
            {
                foreach (string f in Directory.GetFiles(dir, "*.7z"))
                    if (!IsNonFirstVolume(f)) into.Add(f);
                foreach (string f in Directory.GetFiles(dir, "*.zip"))
                    if (!IsNonFirstVolume(f)) into.Add(f);
                foreach (string f in Directory.GetFiles(dir, "*.001")) into.Add(f);
                foreach (string d in Directory.GetDirectories(dir)) CollectFromFolder(d, into);
            }
            catch { }
        }

        private void RefreshList()
        {
            _list.BeginUpdate();
            _list.Items.Clear();
            foreach (string f in _items)
            {
                var it = new ListViewItem(f);
                it.SubItems.Add("");
                _list.Items.Add(it);
            }
            _list.EndUpdate();
        }

        private void RemoveSelected()
        {
            foreach (int i in _list.SelectedIndices.Cast<int>().OrderByDescending(x => x).ToArray())
                _items.RemoveAt(i);
            RefreshList();
        }

        private void ClearAll()
        {
            if (IsBusy()) return;
            _items.Clear();
            RefreshList();
            _lblStatus.Text = "列表已清空。";
        }

        private bool IsBusy()
        {
            return _worker != null && _worker.IsAlive;
        }

        private void SetBusy(bool busy)
        {
            _btnStart.Enabled = !busy;
            _btnCancel.Enabled = busy;
            _btnClear.Enabled = !busy;
            _txtPwd.ReadOnly = busy;
            _chkDeep.Enabled = !busy;
            _dropPanel.Enabled = !busy;
        }

        private void UI(Action a)
        {
            try
            {
                if (IsDisposed || !IsHandleCreated) return;
                if (InvokeRequired) BeginInvoke(a);
                else a();
            }
            catch { }
        }

        // ------------------------------------------------------------ 开始验证
        private void DoStart()
        {
            if (IsBusy()) return;

            if (_7zPath == null)
            {
                _7zPath = SevenZipLocator.Find();
                if (_7zPath == null) { MessageBox.Show(this, "未找到 7-Zip,请先安装。", "7z 密码验证"); return; }
            }
            if (_items.Count == 0)
            {
                MessageBox.Show(this, "请先拖入要验证的压缩包。", "7z 密码验证");
                return;
            }
            string pwd = _txtPwd.Text;
            if (pwd.Length == 0)
            {
                MessageBox.Show(this, "请输入要验证的密码。", "7z 密码验证");
                _txtPwd.Focus();
                return;
            }
            if (pwd.IndexOf('"') >= 0)
            {
                MessageBox.Show(this, "密码里不能包含英文双引号 \"。", "7z 密码验证");
                return;
            }

            bool deep = _chkDeep.Checked;
            string[] files = _items.ToArray();
            var runner = new SevenZipRunner { SevenZipPath = _7zPath };
            _runner = runner;

            SetBusy(true);
            _bar.Value = 0;
            _lblStatus.ForeColor = Color.DimGray;
            _lblStatus.Text = "正在验证…";

            _worker = new Thread(delegate()
            {
                int ok = 0, wrong = 0, other = 0;
                string firstWrong = null;
                for (int i = 0; i < files.Length; i++)
                {
                    if (runner.CancelRequested) break;
                    int idx = i;
                    string file = files[i];
                    UI(delegate { SetRow(idx, "…验证中", Color.DimGray); });

                    CheckOutcome oc = CheckCore.Check(runner, file, pwd, deep, delegate(int p)
                    {
                        int pp = Math.Max(0, Math.Min(100, p));
                        UI(delegate { _lblStatus.Text = "正在完整校验: " + Path.GetFileName(file) + "  " + pp + "%"; });
                    });

                    if (oc.Result == CheckResult.Cancelled) break;
                    string msg = oc.Message;
                    switch (oc.Result)
                    {
                        case CheckResult.Ok: ok++; break;
                        case CheckResult.WrongPassword:
                            wrong++;
                            if (firstWrong == null) firstWrong = file;
                            break;
                        default: other++; break;
                    }
                    CheckResult res = oc.Result;
                    UI(delegate
                    {
                        if (res == CheckResult.Ok) SetRow(idx, "✓ " + msg, Color.ForestGreen);
                        else if (res == CheckResult.WrongPassword) SetRow(idx, "✗ " + msg, Color.Firebrick);
                        else SetRow(idx, "⚠ " + msg, Color.DarkOrange);
                        _bar.Value = (int)((idx + 1) * 100.0 / files.Length);
                    });
                }

                string summary;
                Color col;
                if (runner.CancelRequested)
                {
                    summary = "已取消。";
                    col = Color.DimGray;
                }
                else if (wrong == 0 && other == 0)
                {
                    summary = "✓ 全部 " + ok + " 个压缩包密码都正确!";
                    col = Color.ForestGreen;
                }
                else if (ok == 0 && wrong == files.Length)
                {
                    summary = "✗ " + wrong + " 个压缩包密码全部错误。请核对密码(注意大小写、全角半角、输入法)。";
                    col = Color.Firebrick;
                }
                else
                {
                    summary = "结果: 密码正确 " + ok + " 个,密码错误 " + wrong + " 个"
                              + (other > 0 ? ",其他问题 " + other + " 个" : "") + "。"
                              + (firstWrong != null ? "(例如 " + Path.GetFileName(firstWrong) + " 密码不对)" : "");
                    col = Color.DarkOrange;
                }
                UI(delegate
                {
                    SetBusy(false);
                    _lblStatus.ForeColor = col;
                    _lblStatus.Text = summary;
                });
            });
            _worker.IsBackground = true;
            _worker.Start();
        }

        private void SetRow(int idx, string text, Color color)
        {
            if (idx < 0 || idx >= _list.Items.Count) return;
            ListViewItem it = _list.Items[idx];
            it.UseItemStyleForSubItems = false;
            it.SubItems[1].Text = text;
            it.SubItems[1].ForeColor = color;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);
            if (IsBusy())
            {
                if (MessageBox.Show(this, "正在验证,确定要退出吗?", "退出确认",
                        MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    e.Cancel = true;
                    return;
                }
                if (_runner != null) _runner.Cancel();
                try { _worker.Join(3000); } catch { }
            }
        }
    }
}
