rule PoshC2_PowerShell_one_liner
{
    meta:
        author = "VMware"
        
    strings:
        $Code_1 = "ServerCertificateValidationCallback" ascii wide nocase
        $Code_2 = "UTF8.GetString" ascii wide nocase
        $Code_3 = "FromBase64String" ascii wide nocase
        $Code_4 = "system.net.webclient" ascii wide nocase
        $Code_5 = "downloadstring" ascii wide nocase
        $Code_6 = ";IEX" ascii wide nocase  // Only the one-liner has commands separated with semicolon
        
        $URI_1 = "/adsense/troubleshooter/1631343" ascii wide nocase
        $URI_2 = "/adServingData/PROD/TMClient/6/8736" ascii wide nocase
        $URI_3 = "/advanced_search" ascii wide nocase
        $URI_4 = "/async/newtab" ascii wide nocase
        $URI_5 = "/babel-polyfill/6.3.14/polyfill.min.js" ascii wide nocase
        $URI_6 = "/bh/sync/aol" ascii wide nocase
        $URI_7 = "/bootstrap/3.1.1/bootstrap.min.js" ascii wide nocase
        $URI_8 = "/branch-locator/search.asp" ascii wide nocase
        $URI_9 = "/business/home.asp" ascii wide nocase
        $URI_10 = "/business/retail-business/insurance.asp" ascii wide nocase
        $URI_11 = "/cdba" ascii wide nocase
        $URI_12 = "/cisben/marketq" ascii wide nocase
        $URI_13 = "/classroom/sharewidget/widget_stable.html" ascii wide nocase
        $URI_14 = "/client_204" ascii wide nocase
        $URI_15 = "/load/pages/index.php" ascii wide nocase
        $URI_16 = "/putil/2018/0/11/po.html" ascii wide nocase
        $URI_17 = "/qqzddddd/2018/load.php" ascii wide nocase
        $URI_18 = "/status/995598521343541248/query" ascii wide nocase
        $URI_19 = "/TOS" ascii wide nocase
        $URI_20 = "/trader-update/history" ascii wide nocase
        $URI_21 = "/types/translation/v1/articles" ascii wide nocase
        $URI_22 = "/uasclient/0.1.34/modules" ascii wide nocase
        $URI_23 = "/usersync/tradedesk" ascii wide nocase
        $URI_24 = "/utag/lbg/main/prod/utag.15.js" ascii wide nocase
        $URI_25 = "/vfe01s/1/vsopts.js" ascii wide nocase
        $URI_26 = "/vssf/wppo/site/bgroup/visitor" ascii wide nocase
        $URI_27 = "/wpaas/load.php" ascii wide nocase
        $URI_28 = "/web/20110920084728" ascii wide nocase
        $URI_29 = "/webhp" ascii wide nocase
        $URI_30 = "/work/embedded/search" ascii wide nocase
        $URI_31 = "/GoPro5/black/2018" ascii wide nocase
        $URI_32 = "/Philips/v902" ascii wide nocase
        

        // "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$MS=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((new-object system.net.webclient).downloadstring"
        $Base64 = "WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8AaQBuAHQATQBhAG4AYQBnAGUAcgBdADoAOgBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAIAA9ACAAewAkAHQAcgB1AGUAfQA7ACQATQBTAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAHMAeQBzAHQAZQBtAC4AbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnA" ascii wide
    
    condition:
        (all of ($Code_*) and 1 of ($URI_*)) or $Base64
}

rule PoshC2_PowerShell_implant
{
    meta:
        author = "VMware"
        
    strings:
        $Code_1 = "ServerCertificateValidationCallback" ascii wide nocase
        $Code_2 = "AesCryptoServiceProvider" ascii wide nocase
        $Code_3 = "FromBase64String" ascii wide nocase
        $Code_4 = "ToBase64String" ascii wide nocase
        $Code_5 = "System.Net.WebProxy" ascii wide nocase
        $Code_6 = "*key*" ascii wide nocase
        $Code_7 = "System.Net.WebClient" ascii wide nocase
        
        $URI_1 = "/adsense/troubleshooter/1631343" ascii wide nocase
        $URI_2 = "/adServingData/PROD/TMClient/6/8736" ascii wide nocase
        $URI_3 = "/advanced_search" ascii wide nocase
        $URI_4 = "/async/newtab" ascii wide nocase
        $URI_5 = "/babel-polyfill/6.3.14/polyfill.min.js" ascii wide nocase
        $URI_6 = "/bh/sync/aol" ascii wide nocase
        $URI_7 = "/bootstrap/3.1.1/bootstrap.min.js" ascii wide nocase
        $URI_8 = "/branch-locator/search.asp" ascii wide nocase
        $URI_9 = "/business/home.asp" ascii wide nocase
        $URI_10 = "/business/retail-business/insurance.asp" ascii wide nocase
        $URI_11 = "/cdba" ascii wide nocase
        $URI_12 = "/cisben/marketq" ascii wide nocase
        $URI_13 = "/classroom/sharewidget/widget_stable.html" ascii wide nocase
        $URI_14 = "/client_204" ascii wide nocase
        $URI_15 = "/load/pages/index.php" ascii wide nocase
        $URI_16 = "/putil/2018/0/11/po.html" ascii wide nocase
        $URI_17 = "/qqzddddd/2018/load.php" ascii wide nocase
        $URI_18 = "/status/995598521343541248/query" ascii wide nocase
        $URI_19 = "/TOS" ascii wide nocase
        $URI_20 = "/trader-update/history" ascii wide nocase
        $URI_21 = "/types/translation/v1/articles" ascii wide nocase
        $URI_22 = "/uasclient/0.1.34/modules" ascii wide nocase
        $URI_23 = "/usersync/tradedesk" ascii wide nocase
        $URI_24 = "/utag/lbg/main/prod/utag.15.js" ascii wide nocase
        $URI_25 = "/vfe01s/1/vsopts.js" ascii wide nocase
        $URI_26 = "/vssf/wppo/site/bgroup/visitor" ascii wide nocase
        $URI_27 = "/wpaas/load.php" ascii wide nocase
        $URI_28 = "/web/20110920084728" ascii wide nocase
        $URI_29 = "/webhp" ascii wide nocase
        $URI_30 = "/work/embedded/search" ascii wide nocase
        $URI_31 = "/GoPro5/black/2018" ascii wide nocase
        $URI_32 = "/Philips/v902" ascii wide nocase

        // "IEX(New-Object IO.StreamReader((New-Object System.IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String"        
        $Base64 = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG0AKABbAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAF0AWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGc" ascii wide

    condition:
        (all of ($Code_*) and 1 of ($URI_*)) or $Base64
}

