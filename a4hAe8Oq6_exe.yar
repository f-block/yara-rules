rule a4hAe8Oq6_exe {
    meta:
        description = "Contains some IoCs for the malware sample with the following hashes. This rule can be used on proxy/dns logs and memory/process dumps."
        sha256_1 = "617974db1e3786cdcc33b57fe387ab262bbfbeb47a5a20818dcd4ab2ecffc57a"
        sha256_2 = "a5c58b5cc0a2fcd5b02bc17147515ab243e325ffd5a7f1ba603f7ea7e65f6331"
        sha256_3 = "dd46d8ec4d4a52af0bc36e6c3720938b54f6c7151298fe1555009c2679ab3a1d"
        sha256_4 = "9c60d945e7684d4f28b160cf4352e276e445119e37c5e5586320bc4f31fd8ccc"
        sha256_5 = "a87b328690898f9bf523bda271e0d2e24835d06e2c5457dfb05362767ff39b38"
        sha256_6 = "f2e5aceed66d1d7e3c16c3aaef81c044da91f12003d7c5280a0f37eefde9ac64"
        family = "Gozi/ISFB/Dreambot/Ursnif"
        author = "Frank Block"
        date = "2019-10-29"
        reference = "https://insinuator.net/2019/10/dissection-of-an-incident-part-2/"

    strings:
        $string1 = "45.10.88.81" ascii wide nocase
        $string2 = "77.87.212.52" ascii wide nocase
        $string3 = "162.255.119.184" ascii wide nocase
        $string4 = "198.54.117.210" ascii wide nocase
        $string5 = "198.54.117.211" ascii wide nocase
        $string6 = "198.54.117.212" ascii wide nocase
        $string7 = "198.54.117.215" ascii wide nocase
        $string8 = "198.54.117.216" ascii wide nocase
        $string9 = "198.54.117.217" ascii wide nocase
        $string10 = "198.54.117.218" ascii wide nocase
        $string11 = "194.87.101.150" ascii wide nocase
        $string12 = "a4hAe8Oq6.exe" ascii wide nocase
        $string13 = "reejosephiney.top" ascii wide nocase
        $string14 = "www.reejosephiney.top" ascii wide nocase
        $string15 = "wr29shaniakobe.xyz" ascii wide nocase
        $string16 = "zkeaganarlie.xyz" ascii wide nocase
        $string17 = "laogxsc3377allison.club" ascii wide nocase
        $string18 = "10291029JSJUYNHG" ascii wide nocase
        $string19 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii wide nocase
        $string20 = "%S=new ActiveXObject('WScript.Shell');%S.Run('powershell.exe Invoke-Expression ([System.Text.Encoding]::ASCII.GetString((Get-ItemProperty \"%S:\\%S\").%s))',0,0);" ascii wide nocase
        $string21 = "mshta \"about:<hta:application><script>moveTo(-898,-989);resizeTo(1,1);eval(new ActiveXObject('WScript.Shell').RegRead('%S\\\\%S\\\\%s'));if(!window.flag)close()</script>\"" ascii wide nocase

    condition:
        any of them
}
