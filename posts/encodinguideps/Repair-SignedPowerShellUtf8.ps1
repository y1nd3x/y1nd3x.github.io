<#
.SYNOPSIS
    Finds and fixes signed PowerShell scripts whose signature shows NotSigned,
    or that cannot be signed, because of how the script file's text is encoded.
 
.DESCRIPTION
    -Mode Scan (default, read-only)
        Reports possible encoding issues:
          None                     No encoding issue detected.
          MalformedUtf8            UTF-8 file containing invalid UTF-8 bytes.
          Utf8WithoutBom           UTF-8 file without a BOM that is not valid
                                   text in this machine's code page.
          NotValidInCodePage       Not valid text in this machine's code page.
          CodePageTextReadAsUtf8   Code-page text (for example Shift-JIS) that
                                   Windows reads as UTF-8.
 
    -Mode Repair (temporary fix, keeps the existing signature)
        Attempts to write a copy with the same signed text, then checks whether
        its existing signature is Valid. Script text is not improved;
        characters that were already unreadable stay unreadable.
        For Utf8WithoutBom and NotValidInCodePage, run on a machine with the
        same system code page as the machine that signed the file.
        Not available for CodePageTextReadAsUtf8; use ConvertToUtf8Bom.
 
    -Mode ConvertToUtf8Bom (long-term fix, requires re-signing)
        Writes a copy saved as UTF-8 with BOM with the old signature removed.
        Review it and sign it again.
 
    The source file is never modified. Requires a FullLanguage session; on
    machines with application control, sign this script with a trusted
    certificate first.
 
.PARAMETER Path
    Scan: one or more files or folders. Repair / ConvertToUtf8Bom: one file.
 
.PARAMETER Recurse
    Scan: include subfolders.
 
.PARAMETER OutputPath
    Repair / ConvertToUtf8Bom: destination. Defaults to
    <name>.repaired.<ext> or <name>.utf8bom.<ext> next to the source.
 
.PARAMETER SourceCodePage
    ConvertToUtf8Bom: code page the file was written in (for example 932),
    when it cannot be detected. Encodings that cannot be decoded strictly by
    Windows are not supported; use an editor to convert those files instead.
 
.EXAMPLE
    .\Repair-SignedPowerShellUtf8.ps1 -Path C:\Scripts -Recurse
 
.EXAMPLE
    .\Repair-SignedPowerShellUtf8.ps1 -Mode Repair -Path C:\Scripts\Deploy.ps1
 
.EXAMPLE
    .\Repair-SignedPowerShellUtf8.ps1 -Mode ConvertToUtf8Bom -Path C:\Scripts\Deploy.ps1
#>
 
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string[]] $Path,
 
    [ValidateSet('Scan', 'Repair', 'ConvertToUtf8Bom')]
    [string] $Mode = 'Scan',
 
    [switch] $Recurse,
 
    [string] $OutputPath,
 
    [int] $SourceCodePage
)
 
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
 
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage')
{
    throw 'This tool must run in a FullLanguage session. On machines with application control, sign this script with a trusted certificate and run it again.'
}
 
if (-not ('SipScriptRepair.Native' -as [type]))
{
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
 
namespace SipScriptRepair
{
    public static class Native
    {
        private const uint MB_ERR_INVALID_CHARS = 0x8;
        private const uint WC_NO_BEST_FIT_CHARS = 0x400;
        private const int ERROR_NO_UNICODE_TRANSLATION = 1113;
        private const int ERROR_INVALID_FLAGS = 1004;
        private const int UnicodeTests =
            0x0001 | 0x0010 | 0x0004 | 0x0040 | 0x0008 |
            0x0080 | 0x0100 | 0x0200 | 0x0400 | 0x1000;
 
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int MultiByteToWideChar(uint codePage, uint flags,
            byte[] input, int inputCount, [Out] char[] output, int outputCount);
 
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int WideCharToMultiByte(uint codePage, uint flags,
            char[] input, int inputCount, [Out] byte[] output, int outputCount,
            IntPtr defaultChar, out int usedDefaultChar);
 
        [DllImport("kernel32.dll")]
        public static extern uint GetACP();
 
        [DllImport("advapi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsTextUnicode(byte[] buffer, int size, ref int result);
 
        // Returns null when strict is true and the bytes are not valid in the code page.
        public static string Decode(uint codePage, bool strict, byte[] bytes)
        {
            if (bytes.Length == 0) { return String.Empty; }
            uint flags = strict ? MB_ERR_INVALID_CHARS : 0;
            int needed = MultiByteToWideChar(codePage, flags, bytes, bytes.Length, null, 0);
            if (needed == 0)
            {
                int error = Marshal.GetLastWin32Error();
                if (strict && error == ERROR_NO_UNICODE_TRANSLATION) { return null; }
                if (strict && error == ERROR_INVALID_FLAGS)
                {
                    throw new NotSupportedException("Code page " + codePage +
                        " does not support strict decoding in this tool. Use an editor to save the file as UTF-8 with BOM, review it, and sign it again.");
                }
                throw new Win32Exception(error);
            }
            char[] output = new char[needed];
            int written = MultiByteToWideChar(codePage, flags, bytes, bytes.Length, output, needed);
            if (written == 0) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            return new string(output, 0, written);
        }
 
        // Returns null when any character cannot be represented exactly.
        public static byte[] EncodeExact(uint codePage, string text)
        {
            if (text.Length == 0) { return new byte[0]; }
            if (codePage == 65001)
            {
                try { return new UTF8Encoding(false, true).GetBytes(text); }
                catch (EncoderFallbackException) { return null; }
            }
            char[] chars = text.ToCharArray();
            int usedDefault;
            int needed = WideCharToMultiByte(codePage, WC_NO_BEST_FIT_CHARS, chars, chars.Length,
                null, 0, IntPtr.Zero, out usedDefault);
            if (needed == 0) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            if (usedDefault != 0) { return null; }
            byte[] output = new byte[needed];
            int written = WideCharToMultiByte(codePage, WC_NO_BEST_FIT_CHARS, chars, chars.Length,
                output, needed, IntPtr.Zero, out usedDefault);
            if (written == 0) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            return usedDefault != 0 ? null : output;
        }
 
        public static bool LooksLikeUnicode(byte[] bytes)
        {
            if (bytes.Length == 0) { return false; }
            int tests = UnicodeTests;
            return IsTextUnicode(bytes, bytes.Length, ref tests);
        }
 
        // Counts UTF-8-shaped multi-byte sequences (lead byte plus the right number of
        // continuation bytes, even if overlong or a surrogate) and bytes that break that shape.
        public static void CountUtf8(byte[] b, out int valid, out int invalid)
        {
            valid = 0; invalid = 0;
            int i = 0;
            while (i < b.Length)
            {
                byte x = b[i];
                if (x < 0x80) { i++; continue; }
                int len = 0;
                if (x >= 0xC0 && x <= 0xDF) { len = 2; }
                else if (x >= 0xE0 && x <= 0xEF) { len = 3; }
                else if (x >= 0xF0 && x <= 0xF7) { len = 4; }
                bool ok = len > 0 && i + len <= b.Length;
                for (int k = 1; ok && k < len; k++)
                {
                    ok = (b[i + k] & 0xC0) == 0x80;
                }
                if (ok) { valid++; i += len; } else { invalid++; i++; }
            }
        }
    }
}
'@
}
 
$scriptExtensions = '.ps1', '.psm1', '.psd1', '.ps1xml', '.psc1', '.cdxml'
$acp = [SipScriptRepair.Native]::GetACP()
 
function Test-Utf8Shape([byte[]] $Bytes)
{
    $remaining = 0
    $allAscii = $true
    foreach ($value in $Bytes)
    {
        [int] $current = $value
        if ($current -ge 0x80) { $allAscii = $false }
        if ($remaining -eq 0)
        {
            if ($current -ge 0x80)
            {
                $shifted = $current
                $ones = 0
                do { $shifted = (($shifted -shl 1) -band 0xFF); $ones++ } while (($shifted -band 0x80) -ne 0)
                $remaining = $ones - 1
                if ($remaining -eq 0) { return $false }
            }
        }
        else
        {
            if (($current -band 0xC0) -ne 0x80) { return $false }
            $remaining--
        }
    }
    return ($remaining -eq 0 -and -not $allAscii)
}
 
# Windows decides how to read a script from its first 32 bytes.
function Get-ReadEncoding([byte[]] $Bytes)
{
    $length = [Math]::Min(32, $Bytes.Length)
    if ($length -le 1) { return 'Ansi' }
    $header = New-Object 'byte[]' $length
    [Array]::Copy($Bytes, $header, $length)
 
    if (($header[0] -eq 0xFF -and $header[1] -eq 0xFE) -or ($header[0] -eq 0xFE -and $header[1] -eq 0xFF)) { return 'Utf16' }
    if ($length -gt 2 -and $header[0] -eq 0xEF -and $header[1] -eq 0xBB -and $header[2] -eq 0xBF) { return 'Utf8' }
    if ([SipScriptRepair.Native]::LooksLikeUnicode($header)) { return 'Utf16' }
    if (Test-Utf8Shape $header) { return 'Utf8' }
    return 'Ansi'
}
 
function Get-ScriptState([string] $FilePath)
{
    $bytes = [IO.File]::ReadAllBytes($FilePath)
    $readAs = Get-ReadEncoding $bytes
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    $validUtf8 = $null -ne [SipScriptRepair.Native]::Decode(65001, $true, $bytes)
    $issue = 'None'
 
    if ($readAs -eq 'Utf8' -and -not $validUtf8)
    {
        $good = 0; $bad = 0
        [SipScriptRepair.Native]::CountUtf8($bytes, [ref] $good, [ref] $bad)
        $issue = if ($hasBom -or $good -ge $bad) { 'MalformedUtf8' } else { 'CodePageTextReadAsUtf8' }
    }
    elseif ($readAs -eq 'Ansi' -and $null -eq [SipScriptRepair.Native]::Decode($acp, $true, $bytes))
    {
        $issue = if ($validUtf8) { 'Utf8WithoutBom' } else { 'NotValidInCodePage' }
    }
 
    [pscustomobject]@{ Bytes = $bytes; ReadAs = $readAs; HasBom = $hasBom; ValidUtf8 = $validUtf8; Issue = $issue }
}
 
function Get-Action([string] $Issue)
{
    switch ($Issue)
    {
        'None'                   { 'No action needed.' }
        'MalformedUtf8'          { 'Temporary: -Mode Repair. Long-term: -Mode ConvertToUtf8Bom and re-sign.' }
        'Utf8WithoutBom'         { "Temporary: -Mode Repair on a machine with code page $acp (same as signer). Long-term: -Mode ConvertToUtf8Bom and re-sign." }
        'NotValidInCodePage'     { "Temporary: -Mode Repair on a machine with code page $acp (same as signer). Long-term: -Mode ConvertToUtf8Bom and re-sign." }
        'CodePageTextReadAsUtf8' { "-Mode ConvertToUtf8Bom on a machine with the code page the file was written in (or use -SourceCodePage), then re-sign." }
    }
}
 
function Resolve-SingleFile
{
    if ($Path.Count -ne 1) { throw "-Mode $Mode accepts exactly one file." }
    $item = Get-Item -LiteralPath $Path[0]
    if ($item.PSIsContainer) { throw "-Mode $Mode accepts a file, not a folder." }
    return $item.FullName
}
 
function Get-OutputFile([string] $Source, [string] $Suffix)
{
    $target = $OutputPath
    if ([string]::IsNullOrWhiteSpace($target))
    {
        $target = Join-Path ([IO.Path]::GetDirectoryName($Source)) (
            [IO.Path]::GetFileNameWithoutExtension($Source) + $Suffix + [IO.Path]::GetExtension($Source))
    }
    $provider = $null
    $drive = $null
    $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($target, [ref] $provider, [ref] $drive)
    if ($provider.Name -ne 'FileSystem') { throw 'OutputPath must be a file-system path.' }
    if ([string]::Equals($Source, $target, [StringComparison]::OrdinalIgnoreCase)) { throw 'OutputPath must be different from the source file.' }
    if ([IO.File]::Exists($target)) { throw "The output file already exists: $target" }
    return $target
}
 
function Remove-TerminalSignatureBlock([string] $Text)
{
    $marker = '# SIG # Begin signature block'
    $start = $Text.LastIndexOf($marker, [StringComparison]::Ordinal)
    if ($start -lt 0 -or ($start -gt 0 -and $Text[$start - 1] -ne "`n")) { return $Text }
    $tail = $Text.Substring($start)
    if ($tail -notmatch '\A# SIG # Begin signature block\r?\n(?:#[^\r\n]*\r?\n)*# SIG # End signature block(?:\r?\n)?\z')
    {
        return $Text
    }
 
    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref] $tokens, [ref] $parseErrors)
    $begin = @($tokens | Where-Object {
        $_.Kind -eq 'Comment' -and $_.Extent.StartOffset -eq $start -and $_.Text -ceq $marker
    })
    if ($begin.Count -ne 1)
    {
        throw 'The trailing signature markers are inside script text, not an unambiguous comment block. Review the file and remove the old signature manually before converting.'
    }
    return $Text.Substring(0, $start)
}
 
function Write-NewFile([string] $Target, [byte[]] $Bytes)
{
    $stream = [IO.File]::Open($Target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length) } finally { $stream.Dispose() }
}
 
switch ($Mode)
{
    'Scan'
    {
        $files = foreach ($p in $Path)
        {
            $item = Get-Item -LiteralPath $p
            if ($item.PSIsContainer)
            {
                Get-ChildItem -LiteralPath $item.FullName -File -Recurse:$Recurse |
                    Where-Object { $scriptExtensions -contains $_.Extension.ToLowerInvariant() }
            }
            else { $item }
        }
 
        foreach ($file in $files)
        {
            $state = Get-ScriptState $file.FullName
            [pscustomobject]@{
                Path            = $file.FullName
                Issue           = $state.Issue
                SignatureStatus = (Get-AuthenticodeSignature -LiteralPath $file.FullName).Status
                CodePage        = $acp
                Action          = Get-Action $state.Issue
            }
        }
    }
 
    'Repair'
    {
        $source = Resolve-SingleFile
        $state = Get-ScriptState $source
 
        if ($state.Issue -eq 'None')
        {
            throw "This file has no text-encoding issue, so Repair does not apply. If its signature is not Valid, the file was changed after signing or the signing certificate is not trusted."
        }
 
        if ($state.Issue -eq 'CodePageTextReadAsUtf8')
        {
            throw "This file contains code-page text (for example Shift-JIS) that Windows reads as UTF-8. Repair would replace that text with '?' characters. Use -Mode ConvertToUtf8Bom and sign the file again."
        }
 
        if ($state.ReadAs -eq 'Utf8')
        {
            $codePage = 65001
            $text = [SipScriptRepair.Native]::Decode(65001, $false, $state.Bytes)
            $repaired = (New-Object System.Text.UTF8Encoding($false, $true)).GetBytes($text)
        }
        else
        {
            $codePage = $acp
            $text = [SipScriptRepair.Native]::Decode($acp, $false, $state.Bytes)
            $repaired = [SipScriptRepair.Native]::EncodeExact($acp, $text)
            if ($null -eq $repaired)
            {
                throw "This file cannot be repaired on code page $acp. Use -Mode ConvertToUtf8Bom and sign the file again."
            }
        }
 
        if (-not [string]::Equals($text, [SipScriptRepair.Native]::Decode($codePage, $true, $repaired), [StringComparison]::Ordinal) -or
            (Get-ReadEncoding $repaired) -ne $state.ReadAs)
        {
            throw 'Repair could not produce an identical copy of the signed text. Use -Mode ConvertToUtf8Bom and sign the file again.'
        }
 
        $target = Get-OutputFile $source '.repaired'
        Write-NewFile $target $repaired
        $status = (Get-AuthenticodeSignature -LiteralPath $target).Status
 
        [pscustomobject]@{
            SourcePath      = $source
            RepairedPath    = $target
            Issue           = $state.Issue
            CodePage        = $codePage
            SignatureStatus = $status
        }
 
        if ($status -ne 'Valid')
        {
            Write-Warning "The repaired copy's signature is $status. The file may have been signed on a machine with a different code page, or changed after signing. Use -Mode ConvertToUtf8Bom and sign it again. Do not deploy the repaired copy."
        }
    }
 
    'ConvertToUtf8Bom'
    {
        $source = Resolve-SingleFile
        $state = Get-ScriptState $source
 
        if ($PSBoundParameters.ContainsKey('SourceCodePage'))
        {
            $text = [SipScriptRepair.Native]::Decode([uint32] $SourceCodePage, $true, $state.Bytes)
            if ($null -eq $text) { throw "The file is not valid text in code page $SourceCodePage." }
            $from = "CodePage $SourceCodePage"
        }
        elseif ($state.ReadAs -eq 'Utf16')
        {
            throw 'This file is UTF-16 and has no text-encoding issue. Conversion is not needed.'
        }
        elseif ($state.ValidUtf8)
        {
            $text = [SipScriptRepair.Native]::Decode(65001, $false, $state.Bytes)
            $from = 'UTF-8'
        }
        elseif ($state.Issue -eq 'MalformedUtf8')
        {
            $text = [SipScriptRepair.Native]::Decode(65001, $false, $state.Bytes)
            $from = 'UTF-8 (invalid bytes replaced)'
            Write-Warning "Invalid bytes were replaced with the '?' replacement character (U+FFFD). Review the converted file before signing."
        }
        else
        {
            $text = [SipScriptRepair.Native]::Decode($acp, $true, $state.Bytes)
            if ($null -eq $text) { throw "Could not detect the file's encoding. Run again with -SourceCodePage set to the code page the file was written in (for example 932)." }
            $from = "CodePage $acp"
        }
 
        $text = $text.TrimStart([char] 0xFEFF)
        $text = Remove-TerminalSignatureBlock $text
 
        $encoding = New-Object System.Text.UTF8Encoding($true, $true)
        $target = Get-OutputFile $source '.utf8bom'
        Write-NewFile $target ($encoding.GetPreamble() + $encoding.GetBytes($text))
 
        [pscustomobject]@{
            SourcePath = $source
            OutputPath = $target
            ReadFrom   = $from
            NextStep   = "Review the file, then sign it: Set-AuthenticodeSignature -FilePath '$target' -Certificate <cert>"
        }
    }
}