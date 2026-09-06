// ============================================================================
//  7zBackup.cs —— 7z 加密备份小工具
//
//  用途: 把文件/文件夹拖进窗口,输入密码,回车,即生成 AES-256 加密 +
//        文件名加密(-mhe)的 .7z 压缩包,适合上传网盘做备份。
//
//  编译: 运行 build.bat(使用 Windows 自带的 .NET Framework C# 编译器,
//        无需安装任何开发环境)。生成单文件 7zBackup.exe。
//
//  自检: 7zBackup.exe --selftest  (无界面,结果写入 selftest_result.txt)
// ============================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace SevenZipBackup
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

    // ------------------------------------------------------------------ 设置
    // 只保存界面选项,出于安全考虑绝不保存密码。
    internal static class Settings
    {
        public static string OutputDir = "";
        public static int LevelIndex = 1;
        public static int VolumeIndex = 0;
        public static bool AutoTest = true;
        public static bool SplitMode = false;
        public static bool MakeManifest = true;
        public static bool ExcludeJunk = true;
        public static int CustomVolumeMB = 0;

        private static string FilePath()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "7zBackup.ini");
        }

        public static void Load()
        {
            try
            {
                if (!File.Exists(FilePath())) return;
                foreach (string raw in File.ReadAllLines(FilePath(), Encoding.UTF8))
                {
                    string line = raw.Trim();
                    if (line.Length == 0 || line.StartsWith("#") || line.StartsWith(";")) continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string k = line.Substring(0, eq).Trim();
                    string v = line.Substring(eq + 1).Trim();
                    if (k == "OutputDir") OutputDir = v;
                    else if (k == "LevelIndex") { int t; if (int.TryParse(v, out t)) LevelIndex = t; }
                    else if (k == "VolumeIndex") { int t; if (int.TryParse(v, out t)) VolumeIndex = t; }
                    else if (k == "AutoTest") AutoTest = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                    else if (k == "SplitMode") SplitMode = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                    else if (k == "MakeManifest") MakeManifest = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                    else if (k == "ExcludeJunk") ExcludeJunk = (v == "1" || v.Equals("true", StringComparison.OrdinalIgnoreCase));
                    else if (k == "CustomVolumeMB") { int t; if (int.TryParse(v, out t)) CustomVolumeMB = t; }
                }
            }
            catch { }
        }

        public static void Save()
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("# 7z加密备份 设置文件(出于安全考虑,这里不会保存密码)");
                sb.AppendLine("OutputDir=" + OutputDir);
                sb.AppendLine("LevelIndex=" + LevelIndex);
                sb.AppendLine("VolumeIndex=" + VolumeIndex);
                sb.AppendLine("AutoTest=" + (AutoTest ? "1" : "0"));
                sb.AppendLine("SplitMode=" + (SplitMode ? "1" : "0"));
                sb.AppendLine("MakeManifest=" + (MakeManifest ? "1" : "0"));
                sb.AppendLine("ExcludeJunk=" + (ExcludeJunk ? "1" : "0"));
                sb.AppendLine("CustomVolumeMB=" + CustomVolumeMB);
                File.WriteAllText(FilePath(), sb.ToString(), Encoding.UTF8);
            }
            catch { }
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
        public bool Cancelled;
        public string Output = "";
        public string Error = "";
        public TimeSpan Elapsed;
    }

    internal class SevenZipRunner
    {
        public string SevenZipPath;
        public volatile bool CancelRequested;
        private Process _proc;
        private readonly object _lock = new object();

        public RunResult Run(string workDir, string[] args, Action<int, string> onProgress)
        {
            var psi = new ProcessStartInfo();
            psi.FileName = SevenZipPath;
            psi.Arguments = JoinArgs(args);
            if (!string.IsNullOrEmpty(workDir)) psi.WorkingDirectory = workDir;
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.CreateNoWindow = true;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;

            var sw = Stopwatch.StartNew();
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
                    try
                    {
                        string e;
                        while ((e = p.StandardError.ReadLine()) != null)
                        {
                            lock (sbErr) sbErr.AppendLine(e);
                        }
                    }
                    catch { }
                });
                errThread.IsBackground = true;
                errThread.Start();

                Regex pct = new Regex("^\\s*(\\d{1,3})%\\s*(.*)$");
                string line;
                while ((line = p.StandardOutput.ReadLine()) != null)
                {
                    lock (sbOut) sbOut.AppendLine(line);
                    if (onProgress != null)
                    {
                        Match m = pct.Match(line);
                        if (m.Success)
                        {
                            int v;
                            if (int.TryParse(m.Groups[1].Value, out v))
                                onProgress(v, m.Groups[2].Value.Trim());
                        }
                    }
                }
                p.WaitForExit();
                sw.Stop();
                lock (_lock) _proc = null;
                RunResult r = new RunResult();
                r.ExitCode = p.ExitCode;
                r.Output = lockText(sbOut);
                r.Error = lockText(sbErr);
                r.Elapsed = sw.Elapsed;
                r.Cancelled = CancelRequested;
                return r;
            }
        }

        private static string lockText(StringBuilder sb)
        {
            lock (sb) return sb.ToString();
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

    // ------------------------------------------------- 规划如何分几次添加文件
    internal class AddCall
    {
        public string WorkDir;
        public string[] Args;
    }

    internal static class ArchivePlanner
    {
        public const string VolumeMultiCallError =
            "分卷压缩只支持「单个文件/文件夹」或「位于同一个文件夹里的多个项目」。\r\n" +
            "请把要备份的项目放到同一个文件夹里再试,或把分卷大小改回「不拆分」。";

        public static List<AddCall> Plan(string[] items)
        {
            List<string> full = items.Select(i => Path.GetFullPath(i))
                                     .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            var calls = new List<AddCall>();
            if (full.Count == 1)
            {
                calls.Add(MakeCall(full[0]));
                return calls;
            }

            List<string> parents = full.Select(i => Path.GetDirectoryName(i))
                                       .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (parents.Count == 1)
            {
                calls.Add(new AddCall
                {
                    WorkDir = parents[0],
                    Args = full.Select(Path.GetFileName).ToArray()
                });
                return calls;
            }

            // 不同位置:先尝试最深公共父目录(保证归档内是相对路径)
            string common = CommonAncestor(full);
            if (!string.IsNullOrEmpty(common) && !IsDriveRoot(common))
            {
                calls.Add(new AddCall
                {
                    WorkDir = common,
                    Args = full.Select(i => MakeRelative(i, common)).ToArray()
                });
                return calls;
            }

            // 兜底:逐项添加;不同文件夹里的同名条目会自动带上父文件夹名
            var nameCount = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (string i in full)
            {
                string n = Path.GetFileName(i);
                nameCount[n] = nameCount.ContainsKey(n) ? nameCount[n] + 1 : 1;
            }
            foreach (string i in full)
            {
                string parent = Path.GetDirectoryName(i);
                string name = Path.GetFileName(i);
                if (nameCount[name] > 1)
                {
                    string grand = Path.GetDirectoryName(parent);
                    if (!string.IsNullOrEmpty(grand))
                    {
                        calls.Add(new AddCall
                        {
                            WorkDir = grand,
                            Args = new[] { Path.GetFileName(parent) + "\\" + name }
                        });
                        continue;
                    }
                }
                calls.Add(MakeCall(i));
            }
            return calls;
        }

        private static AddCall MakeCall(string item)
        {
            return new AddCall
            {
                WorkDir = Path.GetDirectoryName(item),
                Args = new[] { Path.GetFileName(item) }
            };
        }

        private static bool IsDriveRoot(string dir)
        {
            return Path.GetFullPath(dir).TrimEnd('\\').Length <= 2; // "C:"
        }

        private static string CommonAncestor(List<string> items)
        {
            List<string[]> parts = items.Select(i =>
                TrimEmpty(Path.GetDirectoryName(Path.GetFullPath(i))
                    .Split(new[] { Path.DirectorySeparatorChar }))).ToList();
            int n = parts[0].Length;
            foreach (string[] p in parts) n = Math.Min(n, p.Length);
            int k = 0;
            for (; k < n; k++)
            {
                bool same = true;
                foreach (string[] p in parts)
                {
                    if (!string.Equals(p[k], parts[0][k], StringComparison.OrdinalIgnoreCase))
                    {
                        same = false;
                        break;
                    }
                }
                if (!same) break;
            }
            if (k == 0) return null;
            return string.Join("\\", parts[0].Take(k).ToArray()) + "\\";
        }

        private static string[] TrimEmpty(string[] arr)
        {
            int end = arr.Length;
            while (end > 0 && arr[end - 1].Length == 0) end--;
            string[] r = new string[end];
            Array.Copy(arr, r, end);
            return r;
        }

        private static string MakeRelative(string item, string ancestor)
        {
            string full = Path.GetFullPath(item);
            string anc = Path.GetFullPath(ancestor);
            if (!anc.EndsWith("\\")) anc += "\\";
            return full.Substring(anc.Length);
        }
    }

    // ------------------------------------------------- 批量打包规划与校验清单
    internal static class BatchPlanner
    {
        public class Target
        {
            public string Label;      // 显示用名称(不带扩展名)
            public string[] Items;    // 要压缩的内容
            public string OutPath;    // 输出的 .7z 完整路径
        }

        // split=false: 全部合并成一个包(outDirOrFile = .7z 完整路径)
        // split=true : 每个项目各一个包(outDirOrFile = 输出文件夹);
        //              同名项目自动改名 xxx_2.7z,互不覆盖
        public static List<Target> PlanTargets(string[] items, bool split, string outDirOrFile)
        {
            // 去重兜底:同一完整路径重复出现只算一个(主程序 UI 已去重,这里再保险)
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var deduped = new List<string>();
            foreach (string it in items)
            {
                string full;
                try { full = Path.GetFullPath(it); } catch { full = it; }
                if (seen.Add(full)) deduped.Add(it);
            }
            items = deduped.ToArray();

            if (!split)
            {
                string label = items.Length == 1
                    ? Path.GetFileNameWithoutExtension(items[0])
                    : Path.GetFileNameWithoutExtension(outDirOrFile);
                return new List<Target>
                {
                    new Target { Label = label, Items = items, OutPath = outDirOrFile }
                };
            }
            var used = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var list = new List<Target>();
            foreach (string it in items)
            {
                string name = Path.GetFileNameWithoutExtension(it);
                if (string.IsNullOrEmpty(name)) name = "备份";
                foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
                string key = name.ToLowerInvariant();
                int n = used.ContainsKey(key) ? ++used[key] : (used[key] = 1);
                string finalName = (n == 1) ? name : (name + "_" + n);
                list.Add(new Target
                {
                    Label = finalName,
                    Items = new[] { it },
                    OutPath = Path.Combine(outDirOrFile, finalName + ".7z")
                });
            }
            return list;
        }
    }

    internal static class Manifest
    {
        public class Entry
        {
            public string File;
            public long Size;
            public string Hash;
        }

        public static string HashFile(string path, Action<long, long> onProgress)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            using (FileStream fs = File.OpenRead(path))
            {
                // 分块计算,大文件也能实时报告进度
                long total = fs.Length, done = 0, lastReport = -1;
                var buf = new byte[1024 * 1024];
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    sha.TransformBlock(buf, 0, n, buf, 0);
                    done += n;
                    if (onProgress != null && done - lastReport >= 32L * 1024 * 1024)
                    {
                        lastReport = done;
                        onProgress(done, total);
                    }
                }
                sha.TransformFinalBlock(buf, 0, 0);
                byte[] h = sha.Hash;
                var sb = new StringBuilder(h.Length * 2);
                foreach (byte b in h) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        public static string Write(string dir, List<Entry> entries, string modeText)
        {
            // 固定文件名:每次压缩后覆盖更新,避免清单文件越堆越多
            string path = Path.Combine(dir, "校验清单.txt");
            File.WriteAllText(path, BuildText(entries, modeText), Encoding.UTF8);
            return path;
        }

        private static string BuildText(List<Entry> entries, string modeText)
        {
            int nw = 24;
            foreach (Manifest.Entry e in entries) nw = Math.Max(nw, Math.Min(48, e.File.Length));
            var sb = new StringBuilder();
            sb.AppendLine("7z 加密备份 —— 校验清单");
            sb.AppendLine("生成时间: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("打包方式: " + modeText);
            sb.AppendLine("共 " + entries.Count + " 个文件");
            sb.AppendLine();
            sb.AppendLine(Pad("文件名", nw) + "大小".PadLeft(12) + "  SHA-256");
            sb.AppendLine(new string('-', nw + 12 + 70));
            foreach (Manifest.Entry e in entries)
                sb.AppendLine(Pad(e.File, nw) + ArchiveCore.FormatSize(e.Size).PadLeft(12) + "  " + e.Hash);
            sb.AppendLine();
            sb.AppendLine("核对方法: 下载网盘文件后,在命令行运行");
            sb.AppendLine("    certutil -hashfile \"文件名\" SHA256");
            sb.AppendLine("输出与上面一致的指纹,说明文件传输/存储完好。");
            sb.AppendLine("本清单只记录压缩包本身的指纹,不包含包内文件名,可随备份一起上传。");
            sb.AppendLine("每次压缩后本清单会更新(覆盖),只包含最近一次压缩生成的备份包。");
            return sb.ToString();
        }

        private static string Pad(string s, int w)
        {
            if (s.Length >= w) return s + "  ";
            return s + new string(' ', w - s.Length) + "  ";
        }
    }

    // --------------------------------------------------------- 压缩/校验核心
    internal class ArchiveWarningException : Exception
    {
        public ArchiveWarningException(string message) : base(message) { }
    }

    internal static class ArchiveCore
    {
        // 系统垃圾文件(勾选"排除垃圾文件"时不打包):缩略图缓存/桌面配置/macOS 垃圾
        public static readonly string[] JunkExcludes =
        {
            "-xr!Thumbs.db", "-xr!ehthumbs.db", "-xr!desktop.ini", "-xr!.DS_Store"
        };

        // 压缩。onProgress(百分比, 当前文件)。失败抛异常;有警告抛 ArchiveWarningException。
        public static void Archive(SevenZipRunner runner, string[] items, string outPath,
                                   string password, int level, string volume, Action<int, string> onProgress,
                                   string[] extraExcludes = null)
        {
            List<AddCall> calls = ArchivePlanner.Plan(items);
            if (!string.IsNullOrEmpty(volume) && calls.Count > 1)
                throw new InvalidOperationException(ArchivePlanner.VolumeMultiCallError);

            for (int i = 0; i < calls.Count; i++)
            {
                var sw = new List<string>();
                sw.Add("a");
                sw.Add("-t7z");
                sw.Add("-y");
                sw.Add("-mhe=on");           // 加密文件名/目录结构
                sw.Add("-mx=" + level);
                sw.Add("-sccUTF-8");
                sw.Add("-p" + password);      // AES-256 为 7z 格式默认
                if (!string.IsNullOrEmpty(volume)) sw.Add("-v" + volume);
                foreach (string exc in Exclusions(items, outPath)) sw.Add(exc);
                if (extraExcludes != null) foreach (string exc in extraExcludes) sw.Add(exc);
                sw.Add("--");
                sw.Add(outPath);
                sw.AddRange(calls[i].Args);

                int ci = i, count = calls.Count;
                RunResult r = runner.Run(calls[i].WorkDir, sw.ToArray(), delegate(int p, string file)
                {
                    if (onProgress != null) onProgress((ci * 100 + p) / count, file);
                });
                if (r.Cancelled) throw new OperationCanceledException();
                if (r.ExitCode == 1)
                    throw new ArchiveWarningException(
                        "压缩完成但有警告(部分文件可能未包含在备份里,请查看详情):\r\n\r\n" + Tail(Mix(r), 1200));
                if (r.ExitCode != 0)
                    throw new Exception("压缩失败(退出代码 " + r.ExitCode + ")\r\n\r\n" + Tail(Mix(r), 1200));
            }
        }

        public static RunResult Test(SevenZipRunner runner, string target, string password, Action<int, string> onProgress)
        {
            return runner.Run(null, new[] { "t", "-sccUTF-8", "-p" + password, "--", target }, onProgress);
        }

        private static string Mix(RunResult r)
        {
            return ((r.Output ?? "") + "\r\n" + (r.Error ?? "")).Trim();
        }

        public static string Tail(string s, int n)
        {
            if (string.IsNullOrEmpty(s) || s.Length <= n) return s;
            return "……\r\n" + s.Substring(s.Length - n);
        }

        private static IEnumerable<string> Exclusions(string[] items, string outPath)
        {
            // 如果输出文件位于某个被压缩的文件夹内部,把它排除,
            // 避免把正在生成的压缩包也压进去。
            string name = Path.GetFileName(outPath);
            string outDir = null;
            try { outDir = Path.GetDirectoryName(Path.GetFullPath(outPath)); } catch { }
            if (outDir == null) yield break;
            foreach (string it in items)
            {
                string d = Directory.Exists(it)
                    ? Path.GetFullPath(it)
                    : Path.GetDirectoryName(Path.GetFullPath(it));
                if (string.IsNullOrEmpty(d)) continue;
                d = d.TrimEnd('\\');
                if (outDir != null && outDir.TrimEnd('\\').StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase))
                {
                    yield return "-xr!" + name;
                    yield return "-xr!" + name + ".0*";   // 分卷文件
                }
            }
        }

        public static void DeleteArchiveParts(string outPath)
        {
            TryDelete(outPath);
            try
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(outPath));
                string name = Path.GetFileName(outPath);
                if (dir != null && Directory.Exists(dir))
                    foreach (string f in Directory.GetFiles(dir, name + ".0*")) TryDelete(f);
            }
            catch { }
        }

        private static void TryDelete(string f)
        {
            try { if (File.Exists(f)) File.Delete(f); } catch { }
        }

        public static long GetSize(string outPath)
        {
            long total = 0;
            try
            {
                if (File.Exists(outPath)) total += new FileInfo(outPath).Length;
                string dir = Path.GetDirectoryName(Path.GetFullPath(outPath));
                string name = Path.GetFileName(outPath);
                if (dir != null)
                    foreach (string f in Directory.GetFiles(dir, name + ".0*"))
                        total += new FileInfo(f).Length;
            }
            catch { }
            return total;
        }

        public static string FormatSize(long b)
        {
            double d = b;
            string[] u = { "B", "KB", "MB", "GB", "TB" };
            int i = 0;
            while (d >= 1024 && i < 4) { d /= 1024; i++; }
            return d.ToString("0.##") + " " + u[i];
        }
    }

    // ------------------------------------------------------------------ 自检
    // 用法: 7zBackup.exe --selftest  (无界面,结果写入 selftest_result.txt)
    internal static class SelfTest
    {
        public static void RunAll()
        {
            var log = new StringBuilder();
            log.AppendLine("7z加密备份 自检报告  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
            log.AppendLine("7z 路径: " + (SevenZipLocator.Find() ?? "(未找到)"));
            string baseDir = Path.Combine(Path.GetTempPath(),
                "7zBackupSelfTest_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            int fail = 0;
            try
            {
                Action<string, bool> check = delegate(string name, bool ok)
                {
                    log.AppendLine((ok ? "[PASS] " : "[FAIL] ") + name);
                    if (!ok) fail++;
                };

                // 1) 准备测试数据:中文文件名、嵌套文件夹、空文件夹、大文件
                string data = Path.Combine(baseDir, "资料");
                Directory.CreateDirectory(Path.Combine(data, "合同"));
                Directory.CreateDirectory(Path.Combine(data, "照片"));
                Directory.CreateDirectory(Path.Combine(data, "空文件夹"));
                File.WriteAllText(Path.Combine(data, "合同", "2026年度合同_最终版.txt"),
                    "机密内容:合同金额 ¥1,234,567。机密ABC123\r\n", Encoding.UTF8);
                File.WriteAllText(Path.Combine(data, "照片", "旅行照片说明.md"),
                    "# 旅行照片说明\n包含中文、English 与 Unicode 字符。\n", Encoding.UTF8);
                using (FileStream fs = File.Create(Path.Combine(data, "大文件.bin")))
                {
                    uint seed = 123456789;
                    var buf = new byte[65536];
                    for (int i = 0; i < 5; i++) // ~320KB 随机内容
                    {
                        for (int j = 0; j < buf.Length; j++)
                        {
                            seed = seed * 1664525 + 1013904223;
                            buf[j] = (byte)(seed >> 24);
                        }
                        fs.Write(buf, 0, buf.Length);
                    }
                }

                string z = SevenZipLocator.Find();
                check("找到 7z.exe", z != null);
                if (z == null) throw new Exception("未找到 7z.exe");

                string pwd = "测试密码abc123";
                var runner = new SevenZipRunner { SevenZipPath = z };
                string out1 = Path.Combine(baseDir, "备份A.7z");

                // 2) 压缩
                ArchiveCore.Archive(runner, new[] { data }, out1, pwd, 5, null, null);
                check("压缩成功且非空", File.Exists(out1) && new FileInfo(out1).Length > 0);

                // 3) 文件名加密:错误密码连"列出内容"都不行
                RunResult r = runner.Run(null, new[] { "l", "-sccUTF-8", "-pwrongpass123", "--", out1 }, null);
                check("文件名已加密(错误密码无法列出内容)", r.ExitCode != 0);

                // 4) 正确密码可校验、可解压,且内容与原文件一致
                r = ArchiveCore.Test(runner, out1, pwd, null);
                check("备份包校验通过", r.ExitCode == 0);

                string ex = Path.Combine(baseDir, "extracted");
                Directory.CreateDirectory(ex);
                r = runner.Run(null, new[] { "x", "-y", "-sccUTF-8", "-p" + pwd, "-o" + ex, "--", out1 }, null);
                check("解压成功", r.ExitCode == 0);

                string diff;
                bool same = CompareTrees(data, Path.Combine(ex, "资料"), out diff);
                check("解压内容与原文件完全一致" + (same ? "" : " —— " + diff), same);

                // 5) 归档内是相对路径,不泄露本机绝对路径
                //    (条目列表从 "----------" 分隔线之后开始;之前的 "Path =" 是归档自身信息)
                r = runner.Run(null, new[] { "l", "-slt", "-sccUTF-8", "-p" + pwd, "--", out1 }, null);
                string listing = (r.Output ?? "");
                string entryPart = listing;
                int sep = listing.IndexOf("----------", StringComparison.Ordinal);
                if (sep >= 0) entryPart = listing.Substring(sep);
                var entryPaths = new List<string>();
                foreach (string ln in entryPart.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string t = ln.Trim();
                    if (t.StartsWith("Path = ", StringComparison.Ordinal))
                        entryPaths.Add(t.Substring(7).Trim());
                }
                bool noLeak = entryPaths.Count > 0
                    && !entryPaths.Any(p2 => p2.IndexOf("Temp", StringComparison.OrdinalIgnoreCase) >= 0)
                    && entryPaths.Any(p2 => p2.IndexOf("资料", StringComparison.Ordinal) >= 0);
                check("归档内为相对路径(未泄露本机绝对路径)", r.ExitCode == 0 && noLeak);

                // 6) 分卷
                string out2 = Path.Combine(baseDir, "分卷.7z");
                ArchiveCore.Archive(runner, new[] { data }, out2, pwd, 0, "64k", null);
                check("分卷压缩生成 .001/.002/…", File.Exists(out2 + ".001") && File.Exists(out2 + ".002"));

                r = ArchiveCore.Test(runner, out2 + ".001", pwd, null);
                check("分卷校验通过", r.ExitCode == 0);

                string ex2 = Path.Combine(baseDir, "extracted2");
                Directory.CreateDirectory(ex2);
                r = runner.Run(null, new[] { "x", "-y", "-sccUTF-8", "-p" + pwd, "-o" + ex2, "--", out2 + ".001" }, null);
                bool same2 = (r.ExitCode == 0) && CompareTrees(data, Path.Combine(ex2, "资料"), out diff);
                check("分卷解压内容一致" + (same2 ? "" : " —— " + (diff ?? ("退出代码 " + r.ExitCode))), same2);

                string ex3 = Path.Combine(baseDir, "extracted3");
                Directory.CreateDirectory(ex3);
                r = runner.Run(null, new[] { "x", "-y", "-sccUTF-8", "-pwrongpass123", "-o" + ex3, "--", out2 + ".001" }, null);
                check("错误密码无法解压", r.ExitCode != 0);

                // 7) 批量打包规划
                //    不同位置、同名文件夹 → 各自一个包,同名自动改名
                //    同一项目重复出现 → 自动去重(主程序在添加时已去重,这里再兜底)
                string dirA = Path.Combine(baseDir, "项目A");
                string dirB = Path.Combine(baseDir, "项目B");
                Directory.CreateDirectory(dirA); Directory.CreateDirectory(dirB);
                File.WriteAllText(Path.Combine(dirA, "文档.txt"), "A 内容\r\n");
                File.WriteAllText(Path.Combine(dirB, "照片.jpg"), "B 内容\r\n");
                // 两个不同的文件夹都叫"重名",放在不同父目录 → 应得到 重名 与 重名_2
                string dupParent = Path.Combine(baseDir, "P");
                string dupParent2 = Path.Combine(baseDir, "Q");
                string dupDir = Path.Combine(dupParent, "重名");
                string dupDir2 = Path.Combine(dupParent2, "重名");
                Directory.CreateDirectory(dupDir); Directory.CreateDirectory(dupDir2);
                File.WriteAllText(Path.Combine(dupDir, "备份.txt"), "重名1\r\n");
                File.WriteAllText(Path.Combine(dupDir2, "备份.txt"), "重名2\r\n");

                string batchOut = Path.Combine(baseDir, "批量输出");
                Directory.CreateDirectory(batchOut);
                List<BatchPlanner.Target> targets = BatchPlanner.PlanTargets(
                    new[] { dirA, dirB, dirA, dupDir, dupDir2 }, true, batchOut);
                // dirA 出现两次 → 去重后只剩一个 项目A;两个"重名"文件夹 → 重名 与 重名_2
                var names = targets.Select(t => t.Label).ToList();
                int countA = names.Count(n => n.Equals("项目A", StringComparison.OrdinalIgnoreCase));
                bool hasDup = names.Any(n => n.Equals("重名", StringComparison.OrdinalIgnoreCase));
                bool hasDup2 = names.Any(n => n.Equals("重名_2", StringComparison.OrdinalIgnoreCase));
                check("批量规划:相同文件夹去重(项目A只出现一次),同名自动改名(重名/重名_2)",
                    countA == 1 && hasDup && hasDup2 && targets.Count == 4);

                // 8) 批量打包端到端:两个项目各自成一个包,均可通过校验、均密码正确
                //    用与主流程一致的方式(逐包 7z 压缩,不依赖界面线程)
                string b1 = targets.First(t => t.Label.Equals("项目A", StringComparison.OrdinalIgnoreCase)).OutPath;
                string b2 = targets.First(t => t.Label.Equals("项目B", StringComparison.OrdinalIgnoreCase)).OutPath;
                ArchiveCore.Archive(runner, new[] { dirA }, b1, pwd, 5, null, null);
                ArchiveCore.Archive(runner, new[] { dirB }, b2, pwd, 5, null, null);
                bool b1ok = File.Exists(b1) && ArchiveCore.Test(runner, b1, pwd, null).ExitCode == 0;
                bool b2ok = File.Exists(b2) && ArchiveCore.Test(runner, b2, pwd, null).ExitCode == 0;
                check("批量打包:两个项目各自成包且校验通过", b1ok && b2ok);

                // 9) 校验清单:写入 + 指纹正确性
                //    A 包(占位,实测用 b1)hash 与实际文件再算一遍对比
                string expectedHash = Manifest.HashFile(b1, null);
                var entries = new List<Manifest.Entry>
                {
                    new Manifest.Entry { File = Path.GetFileName(b1), Size = new FileInfo(b1).Length, Hash = expectedHash }
                };
                string manpath = Manifest.Write(baseDir, entries, "每个项目各一个包");
                check("校验清单:文件已生成", File.Exists(manpath));
                string manText = File.ReadAllText(manpath, Encoding.UTF8);
                check("校验清单:包含正确 SHA-256 指纹",
                    manText.Contains(expectedHash) && manText.Contains(Path.GetFileName(b1)));
                check("校验清单:固定文件名(校验清单.txt)", Path.GetFileName(manpath) == "校验清单.txt");

                // 10) 垃圾文件排除
                string junkDir = Path.Combine(baseDir, "垃圾测试");
                Directory.CreateDirectory(junkDir);
                File.WriteAllText(Path.Combine(junkDir, "真文件.txt"), "keep\r\n", Encoding.UTF8);
                File.WriteAllText(Path.Combine(junkDir, "Thumbs.db"), "junk\r\n", Encoding.UTF8);
                File.WriteAllText(Path.Combine(junkDir, "desktop.ini"), "junk\r\n", Encoding.UTF8);
                string junkArc = Path.Combine(baseDir, "垃圾排除.7z");
                ArchiveCore.Archive(runner, new[] { junkDir }, junkArc, pwd, 5, null, null, ArchiveCore.JunkExcludes);
                r = runner.Run(null, new[] { "l", "-sccUTF-8", "-p" + pwd, "--", junkArc }, null);
                string junkListing = (r.Output ?? "");
                check("垃圾文件排除:Thumbs.db/desktop.ini 不入包,正常文件保留",
                    r.ExitCode == 0
                    && junkListing.IndexOf("Thumbs.db", StringComparison.OrdinalIgnoreCase) < 0
                    && junkListing.IndexOf("desktop.ini", StringComparison.OrdinalIgnoreCase) < 0
                    && junkListing.IndexOf("真文件.txt", StringComparison.Ordinal) >= 0);
            }
            catch (Exception exx)
            {
                log.AppendLine("[EXCEPTION] " + exx.ToString());
                fail++;
            }
            log.AppendLine();
            log.AppendLine("测试数据目录: " + baseDir);
            log.AppendLine(fail == 0 ? "结果: 全部通过" : ("结果: " + fail + " 项失败"));

            string logPath;
            try { logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "selftest_result.txt"); }
            catch { logPath = Path.Combine(Path.GetTempPath(), "7zBackup_selftest_result.txt"); }
            try { File.WriteAllText(logPath, log.ToString(), Encoding.UTF8); } catch { }
        }

        // 相对路径 -> 是否为文件
        private static Dictionary<string, bool> RelEntries(string root)
        {
            var map = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            Walk(root, "", map);
            return map;
        }

        private static void Walk(string dir, string prefix, Dictionary<string, bool> map)
        {
            foreach (string d in Directory.GetDirectories(dir))
            {
                string rel = prefix.Length == 0 ? Path.GetFileName(d) : prefix + "\\" + Path.GetFileName(d);
                map[rel] = false;
                Walk(d, rel, map);
            }
            foreach (string f in Directory.GetFiles(dir))
                map[prefix.Length == 0 ? Path.GetFileName(f) : prefix + "\\" + Path.GetFileName(f)] = true;
        }

        private static bool CompareTrees(string a, string b, out string diff)
        {
            diff = null;
            if (!Directory.Exists(b)) { diff = "解压目录不存在: " + b; return false; }
            Dictionary<string, bool> ra = RelEntries(a);
            Dictionary<string, bool> rb = RelEntries(b);
            if (ra.Count != rb.Count)
            {
                diff = "条目数量不同: 原始 " + ra.Count + " vs 解压 " + rb.Count;
                return false;
            }
            foreach (KeyValuePair<string, bool> kv in ra)
            {
                bool typeB;
                if (!rb.TryGetValue(kv.Key, out typeB)) { diff = "缺少条目: " + kv.Key; return false; }
                if (typeB != kv.Value) { diff = "类型不同: " + kv.Key; return false; }
                if (kv.Value)
                {
                    byte[] fa = File.ReadAllBytes(Path.Combine(a, kv.Key));
                    byte[] fb = File.ReadAllBytes(Path.Combine(b, kv.Key));
                    if (fa.Length != fb.Length) { diff = "大小不同: " + kv.Key; return false; }
                    for (int i = 0; i < fa.Length; i++)
                        if (fa[i] != fb[i]) { diff = "内容不同: " + kv.Key; return false; }
                }
            }
            return true;
        }
    }

    // ------------------------------------------------------------------ 主窗口
    internal class MainForm : Form
    {
        private const int CUSTOM_VOLUME_INDEX = 6;

        private string _7zPath;
        private Panel _dropPanel;
        private Label _dropLabel, _lblItems, _lblStatus, _lblAdmin, _lblOut;
        private ListBox _list;
        private TextBox _txtPwd, _txtOut;
        private CheckBox _chkShow, _chkTest, _chkSplit, _chkManifest, _chkJunk;
        private ComboBox _cmbLevel, _cmbVolume;
        private Button _btnAddFiles, _btnAddFolder, _btnRemove, _btnClear, _btnBrowse;
        private Button _btnStart, _btnCancel, _btnOpen;
        private ProgressBar _bar;

        private bool _outputEdited;
        private bool _suppressOutEvent;
        private bool _suppressVolEvent;
        private int _customVolumeMB;
        private SevenZipRunner _runner;
        private Thread _worker;
        private string _lastOutputFile;

        public MainForm()
        {
            Settings.Load();
            _7zPath = SevenZipLocator.Find();
            BuildUi();
            ApplyAdminNotice();

            _cmbLevel.SelectedIndex = Math.Max(0, Math.Min(2, Settings.LevelIndex));
            _chkTest.Checked = Settings.AutoTest;
            _chkSplit.Checked = Settings.SplitMode;
            _chkManifest.Checked = Settings.MakeManifest;
            _chkJunk.Checked = Settings.ExcludeJunk;
            if (Settings.CustomVolumeMB > 0) _customVolumeMB = Settings.CustomVolumeMB;
            OnSplitToggled();
            int volIdx = Math.Max(0, Math.Min(_cmbVolume.Items.Count - 1, Settings.VolumeIndex));
            if (volIdx == CUSTOM_VOLUME_INDEX && _customVolumeMB > 0)
            {
                _suppressVolEvent = true;
                _cmbVolume.Items[CUSTOM_VOLUME_INDEX] = "自定义: " + _customVolumeMB + " MB";
                _suppressVolEvent = false;
            }
            if (volIdx == CUSTOM_VOLUME_INDEX && _customVolumeMB <= 0) volIdx = 0;
            _cmbVolume.SelectedIndex = volIdx;

            if (_7zPath == null)
            {
                _lblStatus.ForeColor = Color.Firebrick;
                _lblStatus.Text = "未找到 7-Zip。请先到 https://www.7-zip.org 安装 7-Zip(默认选项即可),然后重新打开本程序。";
                MessageBox.Show(this,
                    "没有找到 7-Zip 的 7z.exe。\r\n请先安装 7-Zip(官网 www.7-zip.org,默认安装即可),再重新打开本程序。",
                    "7z 加密备份", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void BuildUi()
        {
            Text = "7z 加密备份(AES-256 + 文件名加密)";
            Font = new Font("Microsoft YaHei UI", 9F);
            ClientSize = new Size(656, 582);
            MinimumSize = new Size(620, 544);
            StartPosition = FormStartPosition.CenterScreen;

            // 拖放区
            _dropPanel = new Panel();
            _dropPanel.Location = new Point(12, 12);
            _dropPanel.Size = new Size(632, 92);
            _dropPanel.BorderStyle = BorderStyle.FixedSingle;
            _dropPanel.BackColor = Color.FromArgb(245, 248, 252);
            _dropPanel.Cursor = Cursors.Hand;
            _dropLabel = new Label();
            _dropLabel.Dock = DockStyle.Fill;
            _dropLabel.TextAlign = ContentAlignment.MiddleCenter;
            _dropLabel.Text = "把文件 / 文件夹拖到这里\r\n也可点击此区域选择 —— 支持一次拖入多个";
            _dropLabel.ForeColor = Color.FromArgb(70, 90, 120);
            _dropPanel.Controls.Add(_dropLabel);
            Controls.Add(_dropPanel);
            _dropPanel.Click += delegate { AddFilesDialog(); };
            _dropLabel.Click += delegate { AddFilesDialog(); };
            EnableDrop(_dropPanel);
            EnableDrop(_dropLabel);

            // 添加/移除按钮行
            _btnAddFiles = MkBtn("添加文件…", 12, 112, 112);
            _btnAddFolder = MkBtn("添加文件夹…", 130, 112, 126);
            _btnRemove = MkBtn("移除选中", 262, 112, 90);
            _btnClear = MkBtn("清空", 358, 112, 70);
            _btnAddFiles.Click += delegate { AddFilesDialog(); };
            _btnAddFolder.Click += delegate { AddFolderDialog(); };
            _btnRemove.Click += delegate { RemoveSelected(); };
            _btnClear.Click += delegate { _list.Items.Clear(); UpdateCount(); _outputEdited = false; UpdateOutputSuggestion(); };

            _lblItems = new Label();
            _lblItems.AutoSize = true;
            _lblItems.Location = new Point(440, 117);
            _lblItems.ForeColor = Color.DimGray;
            _lblItems.Text = "已添加 0 项";
            Controls.Add(_lblItems);

            // 条目列表
            _list = new ListBox();
            _list.Location = new Point(12, 142);
            _list.Size = new Size(632, 116);
            _list.IntegralHeight = false;
            _list.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            _list.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Delete) { RemoveSelected(); e.Handled = true; }
            };
            _list.DoubleClick += delegate
            {
                try
                {
                    if (_list.SelectedItem != null)
                        Process.Start("explorer.exe", "/select,\"" + _list.SelectedItem + "\"");
                }
                catch { }
            };
            Controls.Add(_list);
            EnableDrop(_list);

            // 密码行
            Label lblPwd = new Label();
            lblPwd.Text = "密码:";
            lblPwd.Location = new Point(12, 272);
            lblPwd.Size = new Size(48, 23);
            Controls.Add(lblPwd);
            _txtPwd = new TextBox();
            _txtPwd.Location = new Point(64, 269);
            _txtPwd.Width = 430;
            _txtPwd.PasswordChar = '\u25CF';
            _txtPwd.MaxLength = 128;
            _txtPwd.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _txtPwd.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Enter)
                {
                    e.SuppressKeyPress = true;
                    e.Handled = true;
                    DoStart();
                }
            };
            Controls.Add(_txtPwd);
            _chkShow = new CheckBox();
            _chkShow.Text = "显示密码";
            _chkShow.AutoSize = true;
            _chkShow.Location = new Point(500, 271);
            _chkShow.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _chkShow.CheckedChanged += delegate
            {
                _txtPwd.PasswordChar = _chkShow.Checked ? '\0' : '\u25CF';
            };
            Controls.Add(_chkShow);

            // 输出行
            _lblOut = new Label();
            _lblOut.Text = "输出到:";
            _lblOut.Location = new Point(12, 304);
            _lblOut.Size = new Size(80, 23);
            Controls.Add(_lblOut);
            _txtOut = new TextBox();
            _txtOut.Location = new Point(94, 301);
            _txtOut.Width = 458;
            _txtOut.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            _txtOut.TextChanged += delegate
            {
                if (!_suppressOutEvent) _outputEdited = true;
            };
            Controls.Add(_txtOut);
            _btnBrowse = MkBtn("浏览…", 554, 300, 90);
            _btnBrowse.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            _btnBrowse.Click += delegate { BrowseOut(); };
            Controls.Add(_btnBrowse);

            // 选项行
            Label lblLevel = new Label();
            lblLevel.Text = "压缩等级:";
            lblLevel.Location = new Point(12, 336);
            lblLevel.Size = new Size(72, 23);
            Controls.Add(lblLevel);
            _cmbLevel = new ComboBox();
            _cmbLevel.DropDownStyle = ComboBoxStyle.DropDownList;
            _cmbLevel.Location = new Point(88, 333);
            _cmbLevel.Width = 200;
            _cmbLevel.Items.Add("仅存储(最快,适合照片/视频)");
            _cmbLevel.Items.Add("标准(推荐)");
            _cmbLevel.Items.Add("极限(体积最小,最慢)");
            Controls.Add(_cmbLevel);

            Label lblVol = new Label();
            lblVol.Text = "分卷大小:";
            lblVol.Location = new Point(308, 336);
            lblVol.Size = new Size(72, 23);
            Controls.Add(lblVol);
            _cmbVolume = new ComboBox();
            _cmbVolume.DropDownStyle = ComboBoxStyle.DropDownList;
            _cmbVolume.Location = new Point(384, 333);
            _cmbVolume.Width = 150;
            _cmbVolume.Items.Add("不拆分");
            _cmbVolume.Items.Add("100 MB");
            _cmbVolume.Items.Add("500 MB");
            _cmbVolume.Items.Add("1 GB");
            _cmbVolume.Items.Add("2 GB");
            _cmbVolume.Items.Add("4 GB");
            _cmbVolume.Items.Add("自定义…");
            _cmbVolume.SelectedIndexChanged += delegate
            {
                if (_cmbVolume.SelectedIndex == CUSTOM_VOLUME_INDEX && !_suppressVolEvent)
                {
                    if (_customVolumeMB <= 0)
                    {
                        int v;
                        if (!PromptInt(this, "自定义分卷大小(单位 MB,例如 800):", "分卷大小", out v))
                        {
                            _suppressVolEvent = true;
                            _cmbVolume.SelectedIndex = 0;
                            _suppressVolEvent = false;
                            return;
                        }
                        if (v < 1) v = 1;
                        if (v > 1048576) v = 1048576;
                        _customVolumeMB = v;
                    }
                    _suppressVolEvent = true;
                    _cmbVolume.Items[CUSTOM_VOLUME_INDEX] = "自定义: " + _customVolumeMB + " MB";
                    _suppressVolEvent = false;
                }
            };
            Controls.Add(_cmbVolume);

            // 校验选项
            _chkTest = new CheckBox();
            _chkTest.Text = "压缩后自动校验备份包完整性(推荐,防止传坏/传错)";
            _chkTest.AutoSize = true;
            _chkTest.Location = new Point(12, 366);
            _chkTest.Checked = true;
            Controls.Add(_chkTest);

            // 垃圾文件排除
            _chkJunk = new CheckBox();
            _chkJunk.Text = "排除垃圾文件(推荐)";
            _chkJunk.AutoSize = true;
            _chkJunk.Location = new Point(334, 366);
            Controls.Add(_chkJunk);

            // 批量模式 / 校验清单
            _chkSplit = new CheckBox();
            _chkSplit.Text = "每个项目各压一个包(批量模式)";
            _chkSplit.AutoSize = true;
            _chkSplit.Location = new Point(12, 390);
            _chkSplit.CheckedChanged += delegate { OnSplitToggled(); };
            Controls.Add(_chkSplit);

            _chkManifest = new CheckBox();
            _chkManifest.Text = "生成校验清单(SHA-256,用于上传后核对)";
            _chkManifest.AutoSize = true;
            _chkManifest.Location = new Point(250, 390);
            Controls.Add(_chkManifest);

            // 按钮行
            _btnStart = MkBtn("开始压缩", 12, 414, 150, 38);
            _btnStart.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            _btnStart.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold);
            _btnStart.BackColor = Color.FromArgb(36, 110, 220);
            _btnStart.ForeColor = Color.White;
            _btnStart.FlatStyle = FlatStyle.System;
            _btnStart.Click += delegate { DoStart(); };
            Controls.Add(_btnStart);

            _btnCancel = MkBtn("取消", 172, 414, 90, 38);
            _btnCancel.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            _btnCancel.Enabled = false;
            _btnCancel.Click += delegate
            {
                if (_runner != null) _runner.Cancel();
                _lblStatus.Text = "正在取消…";
            };
            Controls.Add(_btnCancel);

            _btnOpen = MkBtn("打开所在文件夹", 494, 414, 150, 38);
            _btnOpen.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            _btnOpen.Enabled = false;
            _btnOpen.Click += delegate { OpenOutputFolder(); };
            Controls.Add(_btnOpen);

            // 进度条与状态
            _bar = new ProgressBar();
            _bar.Location = new Point(12, 462);
            _bar.Size = new Size(632, 20);
            _bar.Minimum = 0;
            _bar.Maximum = 100;
            _bar.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(_bar);

            _lblStatus = new Label();
            _lblStatus.Location = new Point(12, 488);
            _lblStatus.Size = new Size(632, 46);
            _lblStatus.ForeColor = Color.DimGray;
            _lblStatus.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            _lblStatus.Text = "准备就绪。添加文件 → 输入密码 → 按回车开始。";
            Controls.Add(_lblStatus);

            _lblAdmin = new Label();
            _lblAdmin.Location = new Point(12, 538);
            _lblAdmin.Size = new Size(632, 34);
            _lblAdmin.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            Controls.Add(_lblAdmin);

            EnableDrop(this);
            ScaleForDpi();
        }

        // ---- 手动 DPI 缩放 -------------------------------------------------
        // WinForms 的 AutoScaleMode 在部分环境(系统级 150% 缩放 + 无清单的
        // winexe)下不生效:字体按 DPI 变大,控件坐标却停留在 96dpi 设计值,
        // 文字就会挤出控件、互相重叠。这里在界面搭建完成后,按真实 DPI 把
        // 所有坐标统一放大,与字体保持一致。
        private static float UiScale = 1f;

        private void ScaleForDpi()
        {
            float f = 1f;
            try { using (Graphics g = CreateGraphics()) f = g.DpiX / 96f; } catch { }
            if (f <= 1.01f) return;
            UiScale = f;

            // 缩放期间先摘掉锚定:否则 ClientSize 变大时,底部/四边锚定的控件
            // 会被锚定布局再推移/拉伸一次,跑出窗口外
            var saved = new List<KeyValuePair<Control, AnchorStyles>>();
            SaveAnchors(this, saved);
            SetAllAnchors(this, AnchorStyles.Top | AnchorStyles.Left);

            ScaleTree(this, f);
            ClientSize = new Size((int)(656 * f), (int)(582 * f));
            MinimumSize = new Size((int)(620 * f), (int)(544 * f));

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
            return MkBtn(text, x, y, w, 26);
        }

        private Button MkBtn(string text, int x, int y, int w, int h)
        {
            Button b = new Button();
            b.Text = text;
            b.Location = new Point(x, y);
            b.Size = new Size(w, h);
            Controls.Add(b);
            return b;
        }

        private void EnableDrop(Control c)
        {
            c.AllowDrop = true;
            c.DragEnter += OnDragEnter;
            c.DragDrop += OnDragDrop;
        }

        private void OnDragEnter(object sender, DragEventArgs e)
        {
            if (e.Data != null && e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
            else
                e.Effect = DragDropEffects.None;
        }

        private void OnDragDrop(object sender, DragEventArgs e)
        {
            try
            {
                string[] arr = e.Data.GetData(DataFormats.FileDrop) as string[];
                if (arr != null && arr.Length > 0) AddPaths(arr);
            }
            catch { }
        }

        private void ApplyAdminNotice()
        {
            if (IsElevated())
            {
                _lblAdmin.ForeColor = Color.Firebrick;
                _lblAdmin.Text = "⚠ 当前以管理员身份运行,Windows 会禁用拖拽功能。请直接双击运行本程序(不要右键\"以管理员身份运行\")。";
            }
            else
            {
                _lblAdmin.ForeColor = Color.Gray;
                _lblAdmin.Text = "提示:密码不会保存在任何地方;密码丢失则备份无法解开,请务必记牢。";
            }
        }

        private static bool IsElevated()
        {
            try
            {
                using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                {
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch { return false; }
        }

        // ---------------------------------------------------------- 列表管理
        private void AddFilesDialog()
        {
            if (IsBusy()) return;
            using (var d = new OpenFileDialog())
            {
                d.Title = "选择要备份的文件(可按住 Ctrl 多选)";
                d.Filter = "所有文件|*.*";
                d.Multiselect = true;
                if (d.ShowDialog(this) == DialogResult.OK) AddPaths(d.FileNames);
            }
        }

        private void AddFolderDialog()
        {
            if (IsBusy()) return;
            using (var d = new FolderBrowserDialog())
            {
                d.Description = "选择要备份的文件夹";
                if (d.ShowDialog(this) == DialogResult.OK) AddPaths(new[] { d.SelectedPath });
            }
        }

        private void AddPaths(string[] paths)
        {
            if (IsBusy()) return;
            var items = _list.Items.Cast<string>().ToList();
            foreach (string raw in paths)
            {
                string n;
                try { n = Path.GetFullPath(raw); } catch { continue; }
                if (!File.Exists(n) && !Directory.Exists(n)) continue;
                bool skip = false;
                for (int i = items.Count - 1; i >= 0; i--)
                {
                    string e = items[i];
                    if (string.Equals(e, n, StringComparison.OrdinalIgnoreCase)) { skip = true; break; }
                    if (IsUnder(n, e)) { skip = true; break; }      // 已包含其父文件夹
                    if (IsUnder(e, n)) items.RemoveAt(i);            // 新的是其父文件夹
                }
                if (!skip) items.Add(n);
            }
            _list.BeginUpdate();
            _list.Items.Clear();
            _list.Items.AddRange(items.ToArray());
            _list.EndUpdate();
            UpdateCount();
            UpdateOutputSuggestion();
        }

        private static bool IsUnder(string child, string ancestor)
        {
            string a = Path.GetFullPath(ancestor);
            if (!a.EndsWith("\\")) a += "\\";
            return Path.GetFullPath(child).StartsWith(a, StringComparison.OrdinalIgnoreCase);
        }

        private void RemoveSelected()
        {
            if (_list.SelectedIndex < 0) return;
            var sel = _list.SelectedItems.Cast<string>().ToList();
            foreach (string it in sel) _list.Items.Remove(it);
            UpdateCount();
            UpdateOutputSuggestion();
        }

        private void UpdateCount()
        {
            _lblItems.Text = "已添加 " + _list.Items.Count + " 项";
        }

        private void OnSplitToggled()
        {
            bool split = _chkSplit != null && _chkSplit.Checked;
            if (_lblOut != null) _lblOut.Text = split ? "输出文件夹:" : "输出到:";
            if (_txtOut == null) return;
            string t = _txtOut.Text.Trim();
            if (split)
            {
                // 批量模式:输出位置是文件夹;若当前填的是 .7z 文件就自动换成它所在的文件夹
                if (t.ToLower().EndsWith(".7z") && t.Length > 4)
                {
                    try
                    {
                        _suppressOutEvent = true;
                        _txtOut.Text = Path.GetDirectoryName(Path.GetFullPath(t));
                        _suppressOutEvent = false;
                    }
                    catch { }
                }
            }
            else if (t.Length > 0 && !t.ToLower().EndsWith(".7z"))
            {
                // 切回合并模式:重新建议一个 .7z 文件名
                _outputEdited = false;
                UpdateOutputSuggestion();
            }
        }

        private void UpdateOutputSuggestion()
        {
            if (_outputEdited) return;
            var items = _list.Items.Cast<string>().ToArray();
            if (items.Length == 0) return;

            if (_chkSplit.Checked)
            {
                string dir2 = null;
                if (items.Length == 1)
                {
                    dir2 = Path.GetDirectoryName(items[0]);
                }
                else if (!string.IsNullOrEmpty(Settings.OutputDir) && Directory.Exists(Settings.OutputDir))
                {
                    dir2 = Settings.OutputDir;
                }
                else
                {
                    dir2 = Path.GetDirectoryName(items[0]);
                }
                if (string.IsNullOrEmpty(dir2) || !Directory.Exists(dir2))
                {
                    if (!string.IsNullOrEmpty(Settings.OutputDir) && Directory.Exists(Settings.OutputDir))
                        dir2 = Settings.OutputDir;
                }
                if (string.IsNullOrEmpty(dir2)) return;
                _suppressOutEvent = true;
                _txtOut.Text = dir2;
                _suppressOutEvent = false;
                return;
            }

            string dir, name;
            if (items.Length == 1)
            {
                dir = Path.GetDirectoryName(items[0]);
                name = Path.GetFileName(items[0]);
            }
            else
            {
                dir = (!string.IsNullOrEmpty(Settings.OutputDir) && Directory.Exists(Settings.OutputDir))
                    ? Settings.OutputDir
                    : Path.GetDirectoryName(items[0]);
                name = "备份_" + DateTime.Now.ToString("yyyy-MM-dd_HHmm");
            }
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                dir = (!string.IsNullOrEmpty(Settings.OutputDir) && Directory.Exists(Settings.OutputDir))
                    ? Settings.OutputDir : dir;
            if (string.IsNullOrEmpty(dir)) return;
            _suppressOutEvent = true;
            _txtOut.Text = Path.Combine(dir, name + ".7z");
            _suppressOutEvent = false;
        }

        private void BrowseOut()
        {
            if (_chkSplit.Checked)
            {
                using (var d = new FolderBrowserDialog())
                {
                    d.Description = "选择批量输出的文件夹(每个项目在这里各生成一个 .7z)";
                    string cur = _txtOut.Text.Trim();
                    if (cur.Length > 0)
                    {
                        try
                        {
                            string dir = Directory.Exists(cur)
                                ? Path.GetFullPath(cur)
                                : Path.GetDirectoryName(Path.GetFullPath(cur));
                            if (Directory.Exists(dir)) d.SelectedPath = dir;
                        }
                        catch { }
                    }
                    if (d.ShowDialog(this) == DialogResult.OK)
                    {
                        _suppressOutEvent = true;
                        _txtOut.Text = d.SelectedPath;
                        _suppressOutEvent = false;
                        _outputEdited = true;
                    }
                }
                return;
            }
            using (var d = new SaveFileDialog())
            {
                d.Title = "选择输出位置";
                d.Filter = "7z 压缩包|*.7z";
                string cur = _txtOut.Text.Trim();
                if (cur.Length > 0)
                {
                    try
                    {
                        d.FileName = Path.GetFileName(cur);
                        string dir = Path.GetDirectoryName(Path.GetFullPath(cur));
                        if (Directory.Exists(dir)) d.InitialDirectory = dir;
                    }
                    catch { }
                }
                if (d.ShowDialog(this) == DialogResult.OK)
                {
                    _suppressOutEvent = true;
                    _txtOut.Text = d.FileName;
                    _suppressOutEvent = false;
                    _outputEdited = true;
                }
            }
        }

        private string GetVolumeSize()
        {
            int i = _cmbVolume.SelectedIndex;
            if (i <= 0) return null;
            switch (i)
            {
                case 1: return "100m";
                case 2: return "500m";
                case 3: return "1g";
                case 4: return "2g";
                case 5: return "4g";
                default: return (_customVolumeMB > 0 ? _customVolumeMB : 100) + "m";
            }
        }

        private void SaveSettingsFromUi()
        {
            try
            {
                string cur = _txtOut.Text.Trim();
                string dir = null;
                if (cur.Length > 0)
                {
                    string full = Path.GetFullPath(cur);
                    if (Directory.Exists(full)) dir = full;
                    else dir = Path.GetDirectoryName(full);
                }
                Settings.OutputDir = (dir != null && Directory.Exists(dir)) ? dir : Settings.OutputDir;
            }
            catch { }
            Settings.LevelIndex = Math.Max(0, _cmbLevel.SelectedIndex);
            Settings.VolumeIndex = Math.Max(0, _cmbVolume.SelectedIndex);
            Settings.AutoTest = _chkTest.Checked;
            Settings.SplitMode = _chkSplit.Checked;
            Settings.MakeManifest = _chkManifest.Checked;
            Settings.ExcludeJunk = _chkJunk.Checked;
            Settings.CustomVolumeMB = _customVolumeMB;
            Settings.Save();
        }

        private bool IsBusy()
        {
            return _worker != null && _worker.IsAlive;
        }

        private void SetBusy(bool busy)
        {
            _btnStart.Enabled = !busy;
            _btnCancel.Enabled = busy;
            _btnAddFiles.Enabled = !busy;
            _btnAddFolder.Enabled = !busy;
            _btnRemove.Enabled = !busy;
            _btnClear.Enabled = !busy;
            _txtPwd.ReadOnly = busy;
            _txtOut.ReadOnly = busy;
            _btnBrowse.Enabled = !busy;
            _cmbLevel.Enabled = !busy;
            _cmbVolume.Enabled = !busy;
            _chkTest.Enabled = !busy;
            _chkSplit.Enabled = !busy;
            _chkManifest.Enabled = !busy;
            _chkJunk.Enabled = !busy;
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

        private void Msg(string text)
        {
            MessageBox.Show(this, text, "7z 加密备份", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ---------------------------------------------------------- 开始压缩
        private void DoStart()
        {
            if (IsBusy()) return;

            if (_7zPath == null)
            {
                _7zPath = SevenZipLocator.Find();
                if (_7zPath == null)
                {
                    Msg("没有找到 7-Zip 的 7z.exe。请先安装 7-Zip(www.7-zip.org)后重试。");
                    return;
                }
            }

            string[] items = _list.Items.Cast<string>().ToArray();
            if (items.Length == 0) { Msg("请先添加要备份的文件或文件夹(拖入或点\"添加文件\")。"); return; }

            string pwd = _txtPwd.Text;
            if (pwd.Length == 0) { Msg("请输入密码。"); _txtPwd.Focus(); return; }
            if (pwd.IndexOf('"') >= 0) { Msg("密码里不能包含英文双引号 \",请换一个密码。"); return; }
            if (pwd.Any(c => c < 32)) { Msg("密码里不能包含换行等控制字符。"); return; }

            bool split = _chkSplit.Checked;
            string outText = _txtOut.Text.Trim();
            if (outText.Length == 0)
            {
                Msg(split
                    ? "请填写输出文件夹(每个项目将在这里各生成一个 .7z)。"
                    : "请填写输出位置(默认已自动填好,也可以点\"浏览…\"修改)。");
                return;
            }

            string capOut;   // 合并模式: .7z 完整路径 / 批量模式: 输出文件夹
            try
            {
                if (split)
                {
                    string t = outText.ToLower().EndsWith(".7z") && outText.Length > 4
                        ? Path.GetDirectoryName(Path.GetFullPath(outText))
                        : Path.GetFullPath(outText);
                    if (!Directory.Exists(t))
                    {
                        if (MessageBox.Show(this, "输出文件夹不存在,要创建它吗?\r\n" + t,
                                "提示", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                            Directory.CreateDirectory(t);
                        else return;
                    }
                    capOut = t;
                }
                else
                {
                    string p = outText.ToLower().EndsWith(".7z") ? outText : outText + ".7z";
                    string outDir = Path.GetDirectoryName(Path.GetFullPath(p));
                    if (!Directory.Exists(outDir))
                    {
                        if (MessageBox.Show(this, "输出目录不存在,要创建它吗?\r\n" + outDir,
                                "提示", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                            Directory.CreateDirectory(outDir);
                        else return;
                    }
                    capOut = Path.GetFullPath(p);
                }
            }
            catch (Exception ex)
            {
                Msg("输出路径无效:" + ex.Message);
                return;
            }

        // 计划本轮要压缩的目标列表
        List<BatchPlanner.Target> targets;
        try { targets = BatchPlanner.PlanTargets(items, split, capOut); }
        catch (Exception ex) { Msg("无法开始:" + ex.Message); return; }

            string vol = GetVolumeSize();
            if (!split)
            {
                // 分卷只支持单个项目或同一文件夹里的多个项目(批量模式不受此限)
                try
                {
                    if (!string.IsNullOrEmpty(vol) && ArchivePlanner.Plan(items).Count > 1)
                    {
                        Msg(ArchivePlanner.VolumeMultiCallError);
                        return;
                    }
                }
                catch (Exception ex) { Msg("无法开始:" + ex.Message); return; }

                foreach (string it in items)
                {
                    if (string.Equals(Path.GetFullPath(it), capOut, StringComparison.OrdinalIgnoreCase))
                    {
                        Msg("输出文件不能与要备份的文件是同一个。请换一个输出位置。");
                        return;
                    }
                }
            }
            else
            {
                foreach (BatchPlanner.Target tg in targets)
                {
                    foreach (string it in tg.Items)
                    {
                        if (string.Equals(Path.GetFullPath(it), tg.OutPath, StringComparison.OrdinalIgnoreCase))
                        {
                            Msg("输出文件不能与要备份的文件是同一个:\r\n" + tg.OutPath);
                            return;
                        }
                    }
                }
            }

            var existing = new List<string>();
            foreach (BatchPlanner.Target tg in targets)
                if (File.Exists(tg.OutPath) || File.Exists(tg.OutPath + ".001")) existing.Add(tg.OutPath);
            if (existing.Count > 0)
            {
                string show = string.Join("\r\n", existing.Take(5).ToArray())
                    + (existing.Count > 5 ? "\r\n… 等共 " + existing.Count + " 个" : "");
                if (MessageBox.Show(this, "以下文件已存在,要覆盖吗?\r\n\r\n" + show,
                        "覆盖确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                    return;
                foreach (string e in existing) ArchiveCore.DeleteArchiveParts(e);
            }

            if (pwd.Length < 8 && MessageBox.Show(this,
                    "密码少于 8 位,被暴力破解的风险较高。\r\n建议使用 12 位以上的长密码。仍要继续吗?",
                    "密码强度提醒", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;

            SaveSettingsFromUi();

            string capPwd = pwd, capVol = vol;
            int capLevel = Math.Max(0, Math.Min(2, _cmbLevel.SelectedIndex));
            int[] levels = { 0, 5, 9 };
            int lvl = levels[capLevel];
            bool capTest = _chkTest.Checked;
            bool capManifest = _chkManifest.Checked;
            bool capJunk = _chkJunk.Checked;
            DateTime t0 = DateTime.Now;

            SetBusy(true);
            _lblStatus.ForeColor = Color.DimGray;
            _lblStatus.Text = "正在压缩…";
            _bar.Value = 0;
            _btnOpen.Enabled = false;

            var runner = new SevenZipRunner { SevenZipPath = _7zPath };
            _runner = runner;
            List<BatchPlanner.Target> capTargets = targets;
            bool capSplit = split;

            _worker = new Thread(delegate()
            {
                var okNames = new List<string>();
                var warnNames = new List<string>();
                var failInfos = new List<string>();
                var manifestEntries = new List<Manifest.Entry>();
                long totalSize = 0;
                bool cancelled = false;
                string firstOut = null;

                // 磁盘空间预检:估算源数据总量,不足就不开始(避免压到一半失败)
                UI(delegate { _lblStatus.Text = "正在统计源数据大小…"; });
                long needBytes = 0;
                foreach (string it0 in items) needBytes += DirSize(it0);
                if (needBytes > 0)
                {
                    try
                    {
                        string outLoc = capSplit ? capOut : Path.GetDirectoryName(Path.GetFullPath(capOut));
                        string root = Path.GetPathRoot(outLoc);
                        if (!string.IsNullOrEmpty(root))
                        {
                            DriveInfo di = new DriveInfo(root);
                            if (di.IsReady && di.AvailableFreeSpace < needBytes)
                            {
                                string needS = ArchiveCore.FormatSize(needBytes);
                                string freeS = ArchiveCore.FormatSize(di.AvailableFreeSpace);
                                UI(delegate
                                {
                                    SetBusy(false);
                                    _bar.Value = 0;
                                    _lblStatus.ForeColor = Color.Firebrick;
                                    _lblStatus.Text = "✗ 输出盘空间不足:预计需要约 " + needS + ",该盘可用 " + freeS + "。请清理空间或换一个输出位置。";
                                });
                                return;
                            }
                        }
                    }
                    catch { }
                }

                for (int i = 0; i < capTargets.Count; i++)
                {
                    if (runner.CancelRequested) { cancelled = true; break; }
                    BatchPlanner.Target tgt = capTargets[i];
                    int idx = i, total = capTargets.Count;
                    string baseName = tgt.Label;
                    string baseCopy = baseName;

                    UI(delegate
                    {
                        _bar.Value = (int)(idx * 100.0 / total);
                        _lblStatus.Text = "(第 " + (idx + 1) + "/" + total + " 个) 正在压缩 " + baseCopy + "…";
                    });

                    bool ok = false, warn = false;
                    string failMsg = null;

                    for (int attempt = 1; attempt <= 2; attempt++)
                    {
                        try
                        {
                            ArchiveCore.Archive(runner, tgt.Items, tgt.OutPath, capPwd, lvl, capVol,
                                delegate(int p, string file)
                                {
                                    int pc = (int)((idx * 100 + p) / (double)total);
                                    string f = file;
                                    UI(delegate
                                    {
                                        _bar.Value = Math.Max(0, Math.Min(100, pc));
                                        _lblStatus.Text = "(第 " + (idx + 1) + "/" + total + " 个) 正在压缩 " +
                                            (string.IsNullOrEmpty(f) ? baseCopy : f) + "  (" + p + "%)";
                                    });
                                }, capJunk ? ArchiveCore.JunkExcludes : null);
                            ok = true;
                            break;
                        }
                        catch (OperationCanceledException) { cancelled = true; break; }
                        catch (ArchiveWarningException) { warn = true; break; }
                        catch (Exception ex)
                        {
                            ArchiveCore.DeleteArchiveParts(tgt.OutPath);
                            if (attempt == 1)
                            {
                                string em = ex.Message;
                                UI(delegate { _lblStatus.Text = "(第 " + (idx + 1) + "/" + total + " 个) " + baseCopy + " 失败,重试一次…"; });
                                continue;
                            }
                            failMsg = ex.Message;
                        }
                    }
                    if (runner.CancelRequested) cancelled = true;
                    if (cancelled && !ok && !warn && failMsg == null)
                        ArchiveCore.DeleteArchiveParts(tgt.OutPath);   // 半成品清理

                    if ((ok || warn) && capTest)
                    {
                        string testTarget = (capVol != null) ? tgt.OutPath + ".001" : tgt.OutPath;
                        UI(delegate { _lblStatus.Text = "(第 " + (idx + 1) + "/" + total + " 个) 正在校验 " + baseCopy + "…"; });
                        RunResult tr = null;
                        try
                        {
                            tr = ArchiveCore.Test(runner, testTarget, capPwd, delegate(int p, string file)
                            {
                                int pc = (int)((idx * 100 + p) / (double)total);
                                UI(delegate
                                {
                                    _bar.Value = Math.Max(0, Math.Min(100, pc));
                                    _lblStatus.Text = "(第 " + (idx + 1) + "/" + total + " 个) 正在校验 " + baseCopy + "… " + p + "%";
                                });
                            });
                        }
                        catch (OperationCanceledException) { cancelled = true; }
                        catch (Exception ex2) { tr = null; failMsg = "校验时出错:" + ex2.Message; }

                        if (!cancelled && tr != null)
                        {
                            if (tr.ExitCode == 0) { /* 校验通过 */ }
                            else if (tr.ExitCode == 1) { warn = true; }
                            else
                            {
                                ArchiveCore.DeleteArchiveParts(tgt.OutPath);
                                ok = false; warn = false;
                                failMsg = "校验失败!备份包可能已损坏,未保留:\r\n" +
                                    ArchiveCore.Tail(((tr.Output ?? "") + "\r\n" + (tr.Error ?? "")).Trim(), 400);
                            }
                        }
                    }

                    if (failMsg == null && (ok || warn))
                    {
                        totalSize += ArchiveCore.GetSize(tgt.OutPath);
                        if (firstOut == null) firstOut = tgt.OutPath;
                        if (warn) warnNames.Add(baseName); else okNames.Add(baseName);

                        if (capManifest)
                        {
                            List<string> parts = new List<string>();
                            if (File.Exists(tgt.OutPath)) parts.Add(tgt.OutPath);
                            else
                            {
                                try
                                {
                                    string d = Path.GetDirectoryName(Path.GetFullPath(tgt.OutPath));
                                    string n = Path.GetFileName(tgt.OutPath);
                                    parts.AddRange(Directory.GetFiles(d, n + ".0*"));
                                    parts.Sort(StringComparer.OrdinalIgnoreCase);
                                }
                                catch { }
                            }
                            foreach (string part in parts)
                            {
                                if (runner.CancelRequested) { cancelled = true; break; }
                                string pn = Path.GetFileName(part);
                                string pnCopy = pn;
                                long pnLen = 0;
                                try { pnLen = new FileInfo(part).Length; } catch { }
                                UI(delegate { _lblStatus.Text = "正在计算指纹: " + pnCopy + "…"; });
                                try
                                {
                                    string ph = Manifest.HashFile(part, delegate(long done, long tot)
                                    {
                                        long d = done, t2 = tot;
                                        UI(delegate
                                        {
                                            _lblStatus.Text = "正在计算指纹: " + pnCopy + "  " +
                                                ArchiveCore.FormatSize(d) + " / " + ArchiveCore.FormatSize(t2);
                                        });
                                    });
                                    manifestEntries.Add(new Manifest.Entry { File = pn, Size = pnLen, Hash = ph });
                                }
                                catch { }
                            }
                        }
                    }
                    else if (failMsg != null)
                    {
                        failInfos.Add(baseName + " —— " + OneLine(failMsg, 120));
                    }
                    if (cancelled) break;
                }

                string manifestPath = null;
                if (capManifest && manifestEntries.Count > 0)
                {
                    try
                    {
                        string mDir = capSplit ? capOut : Path.GetDirectoryName(Path.GetFullPath(capOut));
                        UI(delegate { _lblStatus.Text = "正在写入校验清单…"; });
                        manifestPath = Manifest.Write(mDir, manifestEntries,
                            capSplit ? "每个项目各一个包" : "合并成一个包");
                    }
                    catch { manifestPath = null; }
                }

                string doneMsg;
                Color doneColor;
                bool anyOk;
                int produced = okNames.Count + warnNames.Count;
                TimeSpan elapsed = DateTime.Now - t0;

                if (cancelled)
                {
                    doneColor = Color.DimGray;
                    anyOk = produced > 0;
                    doneMsg = "已取消。" + (produced > 0
                        ? "已完成的 " + produced + " 个压缩包已保留。"
                        : "未完成的文件已删除。")
                        + (manifestPath != null ? " 校验清单: " + Path.GetFileName(manifestPath) : "");
                }
                else if (failInfos.Count == 0 && warnNames.Count == 0)
                {
                    doneColor = Color.ForestGreen;
                    anyOk = true;
                    doneMsg = "✓ 完成!生成 " + produced + " 个压缩包" +
                              (produced > 1 ? "(总大小 " + ArchiveCore.FormatSize(totalSize) + ")" : " " + ArchiveCore.FormatSize(totalSize)) +
                              ",耗时 " + elapsed.ToString(@"mm\:ss") +
                              (capTest ? ",全部通过校验" : "") +
                              (manifestPath != null ? "。校验清单: " + Path.GetFileName(manifestPath) : "") +
                              "。可以上传网盘了。";
                }
                else if (produced == 0)
                {
                    doneColor = Color.Firebrick;
                    anyOk = false;
                    doneMsg = "✗ 全部失败:\r\n" + string.Join("\r\n", failInfos.Take(4).ToArray()) +
                              (failInfos.Count > 4 ? "\r\n… 等共 " + failInfos.Count + " 个" : "");
                }
                else
                {
                    doneColor = Color.DarkOrange;
                    anyOk = true;
                    doneMsg = "⚠ 部分完成:成功 " + okNames.Count + " 个" +
                              (warnNames.Count > 0 ? ",有警告 " + warnNames.Count + " 个(" + string.Join(",", warnNames.ToArray()) + ")" : "") +
                              ",失败 " + failInfos.Count + " 个(" + string.Join(",", failInfos.Select(f2 => f2.Split('—')[0].Trim()).ToArray()) + ")" +
                              ",耗时 " + elapsed.ToString(@"mm\:ss") +
                              (manifestPath != null ? "。校验清单: " + Path.GetFileName(manifestPath) : "");
                }

                string msg = doneMsg;
                Color col = doneColor;
                bool okFlag = anyOk;
                string openTarget = firstOut;
                UI(delegate
                {
                    SetBusy(false);
                    _lblStatus.ForeColor = col;
                    _lblStatus.Text = msg;
                    _btnOpen.Enabled = okFlag && openTarget != null;
                    if (openTarget != null) _lastOutputFile = openTarget;
                    if (!cancelled) _bar.Value = 100;
                });
            });
            _worker.IsBackground = true;
            _worker.Start();
        }

        private static string OneLine(string s, int max)
        {
            string t = (s ?? "").Replace("\r", " ").Replace("\n", " ");
            while (t.Contains("  ")) t = t.Replace("  ", " ");
            t = t.Trim();
            if (t.Length > max) t = t.Substring(0, max) + "…";
            return t;
        }

        // 递归统计文件/文件夹总大小(磁盘空间预检用)
        private static long DirSize(string path)
        {
            try
            {
                if (File.Exists(path)) return new FileInfo(path).Length;
                if (!Directory.Exists(path)) return 0;
                long total = 0;
                foreach (string f in Directory.GetFiles(path)) total += new FileInfo(f).Length;
                foreach (string d in Directory.GetDirectories(path)) total += DirSize(d);
                return total;
            }
            catch { return 0; }
        }

        private void OpenOutputFolder()
        {
            try
            {
                string f = _lastOutputFile;
                if (f == null) return;
                string first = File.Exists(f) ? f : f + ".001";
                string show = File.Exists(first) ? first : Path.GetDirectoryName(Path.GetFullPath(f));
                Process.Start("explorer.exe", "/select,\"" + show + "\"");
            }
            catch { }
        }

        private static bool PromptInt(Control owner, string text, string title, out int value)
        {
            value = 0;
            var lbl = new Label();
            lbl.Text = text;
            lbl.AutoSize = true;
            lbl.Location = new Point(12, 12);
            lbl.MaximumSize = new Size(330, 0);
            var txt = new TextBox();
            txt.Location = new Point(14, 48);
            txt.Width = 200;
            var ok = new Button();
            ok.Text = "确定";
            ok.DialogResult = DialogResult.OK;
            ok.Location = new Point(60, 82);
            ok.Width = 70;
            var cc = new Button();
            cc.Text = "取消";
            cc.DialogResult = DialogResult.Cancel;
            cc.Location = new Point(140, 82);
            cc.Width = 70;
            using (var f = new Form())
            {
                f.Text = title;
                f.FormBorderStyle = FormBorderStyle.FixedDialog;
                f.StartPosition = FormStartPosition.CenterParent;
                f.ClientSize = new Size(240, 126);
                f.Controls.Add(lbl);
                f.Controls.Add(txt);
                f.Controls.Add(ok);
                f.Controls.Add(cc);
                f.AcceptButton = ok;
                f.CancelButton = cc;
                f.MaximizeBox = false;
                f.MinimizeBox = false;
                if (UiScale > 1.01f)
                {
                    ScaleTree(f, UiScale);
                    lbl.MaximumSize = new Size((int)(330 * UiScale), 0);
                    f.ClientSize = new Size((int)(240 * UiScale), (int)(126 * UiScale));
                }
                if (f.ShowDialog(owner) == DialogResult.OK)
                {
                    if (int.TryParse(txt.Text.Trim(), out value)) return true;
                    MessageBox.Show(owner, "请输入数字。", title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return PromptInt(owner, text, title, out value);
                }
            }
            return false;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);
            if (IsBusy())
            {
                if (MessageBox.Show(this, "正在压缩,确定要退出吗?(未完成的压缩将被删除)",
                        "退出确认", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                {
                    e.Cancel = true;
                    return;
                }
                if (_runner != null) _runner.Cancel();
                try { _worker.Join(3000); } catch { }
            }
            SaveSettingsFromUi();
        }
    }
}
