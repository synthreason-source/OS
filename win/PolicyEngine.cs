using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json;

namespace FileSecurityMonitor
{
    /// <summary>
    /// Security policy configuration structure
    /// </summary>
    public class PolicyConfig
    {
        [JsonProperty("policies")]
        public Dictionary<string, SecurityPolicy> Policies { get; set; }
    }

    /// <summary>
    /// Individual security policy for a file type
    /// </summary>
    public class SecurityPolicy
    {
        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("extensions")]
        public string[] Extensions { get; set; }

        [JsonProperty("level")]
        public int Level { get; set; } // 1-5, where 5 is most restrictive

        [JsonProperty("rules")]
        public string[] Rules { get; set; } // require_signature, warn_user, log_only, etc.
    }

    /// <summary>
    /// Policy engine - loads and manages security policies
    /// </summary>
    public class PolicyEngine
    {
        private Dictionary<string, SecurityPolicy> _policies;
        private SecurityPolicy _defaultPolicy;
        public string PolicyFilePath { get; private set; }

        public PolicyEngine(string policyFilePath)
        {
            PolicyFilePath = policyFilePath;
            LoadPolicies();
        }

        private void LoadPolicies()
        {
            try
            {
                if (!File.Exists(PolicyFilePath))
                    throw new FileNotFoundException($"Policy file not found: {PolicyFilePath}");

                string json = File.ReadAllText(PolicyFilePath);
                var config = JsonConvert.DeserializeObject<PolicyConfig>(json);

                _policies = new Dictionary<string, SecurityPolicy>(StringComparer.OrdinalIgnoreCase);

                foreach (var policy in config.Policies.Values)
                {
                    foreach (var ext in policy.Extensions)
                    {
                        _policies[ext.ToLower()] = policy;
                    }
                }

                // Default policy for unknown types (moderate security)
                _defaultPolicy = new SecurityPolicy
                {
                    Name = "Unknown File Type",
                    Level = 2,
                    Rules = new[] { "log_only" }
                };

                Console.WriteLine($"[+] Loaded {_policies.Count} policy rules from {_policies.Values.Distinct().Count()} policies");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to load policies: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Get security policy for a file extension
        /// </summary>
        public SecurityPolicy GetPolicy(string extension)
        {
            if (string.IsNullOrEmpty(extension))
                return _defaultPolicy;

            string normalizedExt = extension.ToLower();
            if (!normalizedExt.StartsWith("."))
                normalizedExt = "." + normalizedExt;

            return _policies.ContainsKey(normalizedExt) 
                ? _policies[normalizedExt] 
                : _defaultPolicy;
        }

        /// <summary>
        /// Reload policies from file
        /// </summary>
        public void ReloadPolicies()
        {
            LoadPolicies();
        }
    }

    /// <summary>
    /// File analysis result
    /// </summary>
    public class FileAnalysisResult
    {
        public string FilePath { get; set; }
        public string Extension { get; set; }
        public string DetectedType { get; set; } // Based on magic bytes, not just extension
        public bool HasValidSignature { get; set; }
        public string SignatureInfo { get; set; }
        public long FileSizeBytes { get; set; }
    }

    /// <summary>
    /// File analyzer - inspects files for type validation and signatures
    /// </summary>
    public class FileInspector
    {
        // Magic bytes (file signatures) for common file types
        private static readonly Dictionary<string, (byte[], string)> MagicNumbers = new()
        {
            { ".exe", (new byte[] { 0x4D, 0x5A }, "PE Executable") },           // MZ (DOS/PE header)
            { ".dll", (new byte[] { 0x4D, 0x5A }, "DLL Library") },             // MZ (DOS/PE header)
            { ".zip", (new byte[] { 0x50, 0x4B }, "ZIP Archive") },             // PK
            { ".pdf", (new byte[] { 0x25, 0x50, 0x44, 0x46 }, "PDF Document") },// %PDF
            { ".jpg", (new byte[] { 0xFF, 0xD8, 0xFF }, "JPEG Image") },        // FFD8FF
            { ".png", (new byte[] { 0x89, 0x50, 0x4E, 0x47 }, "PNG Image") },  // 89PNG
            { ".gif", (new byte[] { 0x47, 0x49, 0x46 }, "GIF Image") },        // GIF
            { ".bat", (new byte[] { 0x40, 0x65, 0x63, 0x68 }, "Batch Script") }, // @echo (simplified)
            { ".ps1", (new byte[] { }, "PowerShell Script") },                  // No specific magic bytes
        };

        /// <summary>
        /// Analyze a file: extension, actual type, signature
        /// </summary>
        public FileAnalysisResult AnalyzeFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return null;

                var fileInfo = new FileInfo(filePath);
                var result = new FileAnalysisResult
                {
                    FilePath = filePath,
                    Extension = fileInfo.Extension.ToLower(),
                    FileSizeBytes = fileInfo.Length
                };

                // Detect actual file type from magic bytes
                DetectFileTypeFromMagicBytes(filePath, result);

                // Check code signature (for executables)
                if (IsExecutable(result.Extension))
                {
                    CheckCodeSignature(filePath, result);
                }

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error analyzing file {filePath}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Detect file type by reading magic bytes
        /// </summary>
        private void DetectFileTypeFromMagicBytes(string filePath, FileAnalysisResult result)
        {
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    byte[] buffer = new byte[4];
                    fs.Read(buffer, 0, 4);

                    // Check against known magic bytes
                    foreach (var kvp in MagicNumbers)
                    {
                        if (kvp.Value.Item1.Length > 0 && 
                            buffer.Take(kvp.Value.Item1.Length).SequenceEqual(kvp.Value.Item1))
                        {
                            result.DetectedType = kvp.Value.Item2;
                            return;
                        }
                    }

                    // If no magic bytes matched, classify as unknown
                    result.DetectedType = "Unknown";
                }
            }
            catch (Exception ex)
            {
                result.DetectedType = "Unable to detect";
            }
        }

        /// <summary>
        /// Check if executable has valid code signature
        /// </summary>
        private void CheckCodeSignature(string filePath, FileAnalysisResult result)
        {
            try
            {
                // Use Windows API to verify signature
                result.HasValidSignature = VerifyFileSignature(filePath);
                
                if (result.HasValidSignature)
                {
                    result.SignatureInfo = "Valid code signature";
                }
                else
                {
                    result.SignatureInfo = "No valid code signature";
                }
            }
            catch (Exception ex)
            {
                result.HasValidSignature = false;
                result.SignatureInfo = $"Signature check failed: {ex.Message}";
            }
        }

        /// <summary>
        /// Verify file signature using Windows API
        /// </summary>
        private bool VerifyFileSignature(string filePath)
        {
            try
            {
                // This is a simplified check
                // For production, use WinVerifyTrust API or SignTool
                
                // Quick method: check for Authenticode signature via PowerShell
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -Command \"Get-AuthenticodeSignature -FilePath '{filePath}' | Select-Object -ExpandProperty Status\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8
                };

                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.WaitForExit(5000);
                    string output = proc.StandardOutput.ReadToEnd().Trim();
                    return output == "Valid";
                }
            }
            catch
            {
                // If signature verification fails, assume unsigned
                return false;
            }
        }

        /// <summary>
        /// Check if file extension is executable
        /// </summary>
        private bool IsExecutable(string extension)
        {
            string[] executableExtensions = { ".exe", ".dll", ".sys", ".drv", ".scr", ".msi", ".com" };
            return executableExtensions.Contains(extension.ToLower());
        }
    }
}
