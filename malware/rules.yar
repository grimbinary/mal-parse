/*
   YARA Rule Set
   Author: Grim
   Date: 2023-08-06
   Identifier: samples
   Reference: @grimbinary
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e {
   meta:
      description = "samples - file 09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "45.83.62.11" fullword wide
      $s4 = "&%a%]sGM" fullword ascii
      $s5 = "CCfdat7" fullword ascii
      $s6 = "qtfptc" fullword ascii
      $s7 = "XUpE}S[" fullword ascii
      $s8 = "Kuvo\"E" fullword ascii
      $s9 = "EtKB=+[<" fullword ascii
      $s10 = "ta6%d)O_1[. " fullword ascii
      $s11 = "nERichK" fullword ascii
      $s12 = "UDDa?Lm" fullword ascii
      $s13 = "/GmFF8%(" fullword ascii
      $s14 = "KYQv&iU" fullword ascii
      $s15 = "F%s:rJi" fullword ascii
      $s16 = "~~~}z~" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "\\7?~|s" fullword ascii
      $s18 = "\\dDnU[" fullword ascii
      $s19 = "\\afK62y" fullword ascii
      $s20 = "\\`1nv3" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19 {
   meta:
      description = "samples - file c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "45.83.62.11" fullword wide
      $s4 = "mh- x^<" fullword ascii
      $s5 = "nERichK" fullword ascii
      $s6 = "EiqvjBW" fullword ascii
      $s7 = "UmUA9bH" fullword ascii
      $s8 = "HQQx\"^" fullword ascii
      $s9 = "IzhhR-F" fullword ascii
      $s10 = "nMSPDc/" fullword ascii
      $s11 = "iZFCk-E" fullword ascii
      $s12 = "QJHsD:-" fullword ascii
      $s13 = ".udO;Z" fullword ascii
      $s14 = "EszeA7X" fullword ascii
      $s15 = "sQOu.}f;" fullword ascii
      $s16 = "4\"eoql\\L(" fullword ascii
      $s17 = "RQoxMub(e" fullword ascii
      $s18 = "+7HRmm!" fullword ascii
      $s19 = "gKtvg~En" fullword ascii
      $s20 = "cpVOfks" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2 {
   meta:
      description = "samples - file 46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "~~|}|}" fullword ascii /* reversed goodware string '}|}|~~' */
      $s4 = "~v}?f+ ul" fullword ascii
      $s5 = "nERichK" fullword ascii
      $s6 = "QNAYK{I" fullword ascii
      $s7 = "!gasMv!&4,<" fullword ascii
      $s8 = "GemNC!C" fullword ascii
      $s9 = "<cuqr?" fullword ascii
      $s10 = "PItURAu" fullword ascii
      $s11 = "HqNXJzg" fullword ascii
      $s12 = "}|{}}~" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "\\Dq8Ku" fullword ascii
      $s14 = "sJW607" fullword ascii
      $s15 = "\\Nq6@]G6" fullword ascii
      $s16 = "D$hd4@" fullword ascii
      $s17 = "j hh>B" fullword ascii
      $s18 = "u-h|5@" fullword ascii
      $s19 = "iWltGD" fullword ascii
      $s20 = "&0:#%c" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443 {
   meta:
      description = "samples - file 149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "45.83.62.11" fullword wide
      $s4 = "oOorlG98" fullword ascii
      $s5 = "nERichK" fullword ascii
      $s6 = "MPNcnqe" fullword ascii
      $s7 = "UPBi@ m" fullword ascii
      $s8 = "iZMpqbNm" fullword ascii
      $s9 = "\\DNb&T" fullword ascii
      $s10 = "\\X8@'{" fullword ascii
      $s11 = "D$hd4@" fullword ascii
      $s12 = "j hh>B" fullword ascii
      $s13 = "u-h|5@" fullword ascii
      $s14 = "sm7aO9" fullword ascii
      $s15 = "bBSk&c" fullword ascii
      $s16 = "iI\"Y{3" fullword ascii
      $s17 = "[wriv>" fullword ascii
      $s18 = "Qj]z\"\\" fullword ascii
      $s19 = "{{|~zy~|" fullword ascii
      $s20 = "[StUl7" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec {
   meta:
      description = "samples - file 258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = ", \"o:\\F\"" fullword ascii
      $s4 = "45.83.62.11" fullword wide
      $s5 = "PsF,djGET" fullword ascii
      $s6 = "nERichK" fullword ascii
      $s7 = "g?pLBfDPfM" fullword ascii
      $s8 = "lzqJiZAU" fullword ascii
      $s9 = "TBJcd=|" fullword ascii
      $s10 = "hIBr&'A" fullword ascii
      $s11 = "LsNSB>C" fullword ascii
      $s12 = "zXim+26" fullword ascii
      $s13 = "TRaDLDj" fullword ascii
      $s14 = "CWxLwM-" fullword ascii
      $s15 = "qnQW*~&[" fullword ascii
      $s16 = "Sonz+9r" fullword ascii
      $s17 = "MmBn^p?4dt" fullword ascii
      $s18 = "UjBj4>tK0" fullword ascii
      $s19 = "tMfUU,m" fullword ascii
      $s20 = "VEOxur[" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93 {
   meta:
      description = "samples - file 3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "45.83.62.11" fullword wide
      $s4 = "s+ h#<" fullword ascii
      $s5 = "nERichK" fullword ascii
      $s6 = "accO,@s" fullword ascii
      $s7 = "Hgll7u(z|p" fullword ascii
      $s8 = "ahUs=Fj" fullword ascii
      $s9 = ".DLC(@" fullword ascii
      $s10 = "ZjeF_YI" fullword ascii
      $s11 = "%DYIlvj'" fullword ascii
      $s12 = "yYoXx9" fullword ascii
      $s13 = "eZWOg7" fullword ascii
      $s14 = "D$hd4@" fullword ascii
      $s15 = "j hh>B" fullword ascii
      $s16 = "u-h|5@" fullword ascii
      $s17 = ":8<6n!Y" fullword ascii
      $s18 = "y$GQ6]" fullword ascii
      $s19 = "TfaFOO" fullword ascii
      $s20 = "|~||~}~|~" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193 {
   meta:
      description = "samples - file b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "9- S=vP" fullword ascii
      $s4 = "1#t* :P" fullword ascii
      $s5 = "Re=m* 5" fullword ascii
      $s6 = "nERichK" fullword ascii
      $s7 = "MxrKCjC" fullword ascii
      $s8 = "EkMg7[wS" fullword ascii
      $s9 = "PTiOLiMz" fullword ascii
      $s10 = "gSvaYdo" fullword ascii
      $s11 = "(^KhrXikHB" fullword ascii
      $s12 = "h .lmL" fullword ascii
      $s13 = "wfYl>an]" fullword ascii
      $s14 = "&mxSY62<:V" fullword ascii
      $s15 = "WeQNq!'" fullword ascii
      $s16 = "E/|.gtt" fullword ascii
      $s17 = "cWBkSxw" fullword ascii
      $s18 = "xqmwOx=;" fullword ascii
      $s19 = "TfSM[ug" fullword ascii
      $s20 = "8oPsBOgp" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e {
   meta:
      description = "samples - file 0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "nERichK" fullword ascii
      $s4 = "UCVJ+jI<" fullword ascii
      $s5 = "BdBps?" fullword ascii
      $s6 = "}`ilnS!A" fullword ascii
      $s7 = "mQoy@?8" fullword ascii
      $s8 = "W:.JWK>\\" fullword ascii
      $s9 = ".Sdo`-(" fullword ascii
      $s10 = "B.ARv#u" fullword ascii
      $s11 = "JyWG._)" fullword ascii
      $s12 = "MBCXAi`" fullword ascii
      $s13 = "HScr=hb*&" fullword ascii
      $s14 = "Bggpty5F" fullword ascii
      $s15 = "RKbAc;uw[" fullword ascii
      $s16 = "zaQg<BG" fullword ascii
      $s17 = "l#FgpfP1=|" fullword ascii
      $s18 = "\\CN}8)" fullword ascii
      $s19 = "\\F)[M.Q%{" fullword ascii
      $s20 = "GmUi62" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a {
   meta:
      description = "samples - file a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "{z{|||" fullword ascii /* reversed goodware string '|||{z{' */
      $s4 = "nERichK" fullword ascii
      $s5 = "eIeZ \"" fullword ascii
      $s6 = "BcVT\"b" fullword ascii
      $s7 = "Q[mWGUsH7" fullword ascii
      $s8 = "boLfwu=" fullword ascii
      $s9 = "}}~}||" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "D$hd4@" fullword ascii
      $s11 = "u-h|5@" fullword ascii
      $s12 = "j hX>B" fullword ascii
      $s13 = "/vm|N-" fullword ascii
      $s14 = "%7Cpor" fullword ascii
      $s15 = "MTODz$" fullword ascii
      $s16 = ".7L'Om" fullword ascii
      $s17 = ".qQ:;t" fullword ascii
      $s18 = "o;`q6!L" fullword ascii
      $s19 = "E_hz.eg" fullword ascii
      $s20 = "Ra*|f\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule d8bae33325cdfe4f3c47747a8bed89d753b58f470c8630ef1390784af3856636 {
   meta:
      description = "samples - file d8bae33325cdfe4f3c47747a8bed89d753b58f470c8630ef1390784af3856636.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d8bae33325cdfe4f3c47747a8bed89d753b58f470c8630ef1390784af3856636"
   strings:
      $s1 = "cThis \"Portable Network Graphics\" image uses an unknown interlace scheme which could not be decoded.-The chunks must be compat" wide
      $s2 = "&ProcessedContent.Description.Font.Name" fullword ascii
      $s3 = "tlCenterLeft)ProcessedContent.Description.Font.Charset" fullword ascii
      $s4 = "Geschwindigkeit!ProcessedContent.Description.Text" fullword ascii
      $s5 = "ssigkeit!ProcessedContent.Description.Text" fullword ascii
      $s6 = "Individuell!ProcessedContent.Description.Text" fullword ascii
      $s7 = "DEFAULT_CHARSET'ProcessedContent.Description.Font.Color" fullword ascii
      $s8 = "Tahoma'ProcessedContent.Description.Font.Style" fullword ascii
      $s9 = "clBlack(ProcessedContent.Description.Font.Height" fullword ascii
      $s10 = "Reply Code already exists: %s'Algorithm %s not permitted in FIPS mode+The specified SASL handlers are not ready!!5Doesn't suppor" wide
      $s11 = "Synchredible.exe" fullword ascii
      $s12 = "synchredible.exe" fullword wide
      $s13 = "Delete records?YWarning: ALL selected records will become the subitems of the drop target item. Continue?" fullword wide
      $s14 = "Error getting SSL method.%Error setting File Descriptor for SSL!Error binding data to SSL socket.+EOF was observed that violates" wide
      $s15 = "http://www.synchredible.com" fullword wide
      $s16 = "3http://crt.usertrust.com/U" fullword ascii
      $s17 = ":Nutzt die unter <B>Optionen</B> festgelegte Konfiguration.%ProcessedContent.Description.Location" fullword ascii
      $s18 = "Synchredible - Promo Downloader" fullword ascii
      $s19 = "LabelJobInfoExecution" fullword ascii
      $s20 = "ProcessedContent.Caption" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule ba2fdc59950c64afa4429a28ff4036f496e519a867c3182e322d78c0eef27952 {
   meta:
      description = "samples - file ba2fdc59950c64afa4429a28ff4036f496e519a867c3182e322d78c0eef27952.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "ba2fdc59950c64afa4429a28ff4036f496e519a867c3182e322d78c0eef27952"
   strings:
      $x1 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve tab at index %d Failed to get object at index %" wide
      $s2 = "TCommonDialogHoB" fullword ascii
      $s3 = "EComponentError4" fullword ascii
      $s4 = "OpenPictureDialog1" fullword ascii
      $s5 = "Default/Menu '%s' is already being used by another form" fullword wide
      $s6 = "IShellFolder," fullword ascii
      $s7 = "DialogsPrB" fullword ascii
      $s8 = ":$:(:0:4:@:D:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
      $s9 = "TabFont.Height" fullword ascii
      $s10 = "TabFont.Charset" fullword ascii
      $s11 = "TabFont.Style" fullword ascii
      $s12 = ":#:*:<:L:T:\\:d:l:t:|:" fullword ascii
      $s13 = "CommonAVI8uC" fullword ascii
      $s14 = "9?9F9]9+:7:D:V:\\:|:" fullword ascii
      $s15 = "OnKeyUpHzC" fullword ascii
      $s16 = "TabFont.Name" fullword ascii
      $s17 = "TComponent$'A" fullword ascii
      $s18 = "IHelpSystem," fullword ascii
      $s19 = "TabFont.Color" fullword ascii
      $s20 = "$Unknown picture file extension (.%s)" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926 {
   meta:
      description = "samples - file 9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926"
   strings:
      $s1 = "StartKeylogger" fullword ascii
      $s2 = "get_encryptedPassword" fullword ascii
      $s3 = "Noth.exe" fullword ascii
      $s4 = "VNXT.exe" fullword wide
      $s5 = "get_KeyboardLoggerTimer" fullword ascii
      $s6 = "WzExWJQsRGTwbJHDKgDyHBLqSrZoPRAGeE.exe" fullword wide
      $s7 = "\\mozglue.dll" fullword wide
      $s8 = "get_processhackerFucked" fullword ascii
      $s9 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s10 = "get_ScreenshotLoggerTimer" fullword ascii
      $s11 = "D:\\Before FprmT\\Document VB project\\FireFox Stub\\FireFox Stub\\obj\\Debug\\VNXT.pdb" fullword ascii
      $s12 = "get_ClipboardLoggerTimer" fullword ascii
      $s13 = "get_VoiceRecordLogger" fullword ascii
      $s14 = "GetOutlookPasswords" fullword ascii
      $s15 = "set_encryptedPassword" fullword ascii
      $s16 = "KeyboardLoggerTimer" fullword ascii
      $s17 = "set_KeyboardLoggerTimer" fullword ascii
      $s18 = "_encryptedPassword" fullword ascii
      $s19 = "KeyLoggerEventArgsEventHandler" fullword ascii
      $s20 = "get_passwords" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943 {
   meta:
      description = "samples - file 8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943"
   strings:
      $s1 = "RICSharpCode.SharpZipLib.Zip.Compression.InflaterDynHeader+<CreateStateMachine>d__7" fullword ascii
      $s2 = "Xmqgijbudgv.exe" fullword wide
      $s3 = "System.Collections.Generic.IEnumerator<System.Boolean>.get_Current" fullword ascii
      $s4 = "Failed to read LZW header" fullword wide
      $s5 = "add_ProcessDirectory" fullword ascii
      $s6 = "remove_ProcessDirectory" fullword ascii
      $s7 = "get_EncryptionOverheadSize" fullword ascii
      $s8 = "EncryptionOverheadSize" fullword ascii
      $s9 = "get_EntryEncryptionMethod" fullword ascii
      $s10 = "AttemptRead" fullword ascii
      $s11 = "Descriptor compressed size mismatch" fullword wide
      $s12 = "The Password property must be set before AES encrypted entries can be added" fullword wide
      $s13 = "Exception during test - '" fullword wide
      $s14 = "Creation of AES encrypted entries is not supported" fullword wide
      $s15 = "Header properties were accessed before header had been successfully read" fullword wide
      $s16 = "Unsupported bits set in the header." fullword wide
      $s17 = "ConfigureEntryEncryption" fullword ascii
      $s18 = "get_SystemDefaultCodePage" fullword ascii
      $s19 = "GetHashAndReset" fullword ascii
      $s20 = "TarExtendedHeaderReader" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule b008e6b92de9b7d2e18fe2712c1c0f2d86fbe86e70093e4c54c490161818992c {
   meta:
      description = "samples - file b008e6b92de9b7d2e18fe2712c1c0f2d86fbe86e70093e4c54c490161818992c.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b008e6b92de9b7d2e18fe2712c1c0f2d86fbe86e70093e4c54c490161818992c"
   strings:
      $s1 = "mcharglaw.com/cgi/" fullword ascii
      $s2 = "outlook.txt" fullword ascii
      $s3 = "\"os_crypt\":{\"encrypted_key\":\"" fullword ascii
      $s4 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsQpxicKRA6x4f1hzg0F83HmS1+TI9qoiPU3FPgG8h61h82dOH/mgppy6HAreq31M5rm38r2fTJnIUF9AzJ87u+FsTXVoGfuG3NKyK" ascii
      $s5 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgt26Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s6 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgsW6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s7 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsQpxicKRA6x4c5zPP8k0sAmb73hE6q4KVSHp+gGQY91N1x8zCwFEG7XzXXpqLuTB4/S207SLSeGxwf+NscZayqWp9QCNFPbuEB/fm" ascii
      $s8 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgtm6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s9 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgtm6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s10 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsQpxicKRA6x4c5zPP8k0sAmb73hE6q4KVSHp+gGQY91N1x8zCwFEG7XzXXpqLuTB4/S207SLSeGxwf+NscZayqWp9QCNFPbuEB/fm" ascii
      $s11 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgtG6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s12 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgtG6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s13 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgt26Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s14 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgtm6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s15 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgtG6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s16 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsQpxicKRA6x4f1hzg0F83HmS1+TI9qoiPU3FPgG8h61h82dOH/mgppy6HAreq31M5rm38r2fTJnIUF9AzJ87u+FsTXVoGfuG3NKyK" ascii
      $s17 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgtG6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s18 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsWpNqfahSxGJgsW6Mz3YKGXW34gszhKe2TnB1tVQt9mBP4dXT32I1vxO8Uur6ykMKii6x7SCHeh8sdOBkeeayrRl/NVdBS7vubPGK" ascii
      $s19 = "CbwFpF7GFiCC2W6siJ5dx7iOzozsQpxicKRA6x4f1hzg0F83HmS1+TI9qoiPU3FPgG8h61h82dOH/mgppy6HAreq31M5rm38r2fTJnIUF9AzJ87u+FsTXVoGfuG3NKyK" ascii
      $s20 = "G7BjtVnTXmWq4FuxxIRG2bvEmrHAZZlld6pD8VE/rTjR/xE0UTH1tEh4uYuWUHZwvUwh6lI81sjT3mFxrCKMR/mkkmErqTH1snSaa0clJsU5bs3y+E9jIXwea+q9dKC/" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

rule sig_215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498 {
   meta:
      description = "samples - file 215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498"
   strings:
      $s1 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
      $s2 = "get_encryptedPassword" fullword ascii
      $s3 = "lfwhUWZlmFnGhDYPudAJ.exe" fullword wide
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s5 = "set_encryptedPassword" fullword ascii
      $s6 = "_encryptedPassword" fullword ascii
      $s7 = "KeyLoggerEventArgsEventHandler" fullword ascii
      $s8 = "KeyLoggerEventArgs" fullword ascii
      $s9 = "get_logins" fullword ascii
      $s10 = "get_encryptedUsername" fullword ascii
      $s11 = "get_passwordField" fullword ascii
      $s12 = "get_timePasswordChanged" fullword ascii
      $s13 = "FFLogins" fullword ascii
      $s14 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s15 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s16 = "get_disabledHosts" fullword ascii
      $s17 = "_encryptedUsername" fullword ascii
      $s18 = "_passwordField" fullword ascii
      $s19 = "set_timePasswordChanged" fullword ascii
      $s20 = "Identifykey" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36 {
   meta:
      description = "samples - file 8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36"
   strings:
      $s1 = "Gikdefjvami.exe" fullword wide
      $s2 = "injectparam" fullword ascii
      $s3 = "ICSharpCode.Adapter.ProcessInitializerAdapter.resources" fullword ascii
      $s4 = "injectvisitor" fullword ascii
      $s5 = "injectres" fullword ascii
      $s6 = "LoginConfiguration" fullword ascii
      $s7 = "LoginService" fullword ascii
      $s8 = "injectpool" fullword ascii
      $s9 = "ManageTemplate" fullword ascii
      $s10 = "PostTemplate" fullword ascii
      $s11 = "processCandidate" fullword ascii
      $s12 = "LoginThread" fullword ascii
      $s13 = "processorPrinter" fullword ascii
      $s14 = "LoginParams" fullword ascii
      $s15 = "LoginField" fullword ascii
      $s16 = "LoginModel" fullword ascii
      $s17 = "LoginParameter" fullword ascii
      $s18 = "LoginWriter" fullword ascii
      $s19 = "LoginCreator" fullword ascii
      $s20 = "ProcessAdvisorRecord" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41 {
   meta:
      description = "samples - file 004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41"
   strings:
      $s1 = "System.Collections.Generic.IEnumerable<SharpCompress.Common.Rar.RarVolume>.GetEnumerator" fullword ascii
      $s2 = "System.Collections.Generic.IEnumerable<SharpCompress.Common.Tar.TarEntry>.GetEnumerator" fullword ascii
      $s3 = "System.Collections.Generic.IEnumerator<SharpCompress.Common.Tar.TarEntry>.get_Current" fullword ascii
      $s4 = "System.Collections.Generic.IEnumerator<SharpCompress.Common.Zip.ZipEntry>.get_Current" fullword ascii
      $s5 = "System.Collections.Generic.IEnumerable<SharpCompress.Common.Zip.ZipEntry>.GetEnumerator" fullword ascii
      $s6 = "System.Collections.Generic.IEnumerator<SharpCompress.Common.Rar.RarVolume>.get_Current" fullword ascii
      $s7 = "Jmmgbxriu.exe" fullword wide
      $s8 = "System.Collections.Generic.IEnumerator<SharpCompress.Common.SevenZip.SevenZipVolume>.get_Current" fullword ascii
      $s9 = "System.Collections.Generic.IEnumerable<SharpCompress.Common.SevenZip.SevenZipVolume>.GetEnumerator" fullword ascii
      $s10 = "System.Collections.Generic.IEnumerable<SharpCompress.Common.GZip.GZipEntry>.GetEnumerator" fullword ascii
      $s11 = "System.Collections.Generic.IEnumerator<SharpCompress.Common.GZip.GZipEntry>.get_Current" fullword ascii
      $s12 = "System.Collections.Generic.IEnumerator<SharpCompress.Common.SevenZip.SevenZipEntry>.get_Current" fullword ascii
      $s13 = "System.Collections.Generic.IEnumerable<SharpCompress.Common.SevenZip.SevenZipEntry>.GetEnumerator" fullword ascii
      $s14 = "System.Collections.Generic.IEnumerator<SharpCompress.Archives.Tar.TarArchiveEntry>.get_Current" fullword ascii
      $s15 = "System.Collections.Generic.IEnumerable<SharpCompress.Archives.Rar.RarArchiveEntry>.GetEnumerator" fullword ascii
      $s16 = "System.Collections.Generic.IEnumerable<SharpCompress.Readers.Rar.RarReaderEntry>.GetEnumerator" fullword ascii
      $s17 = "System.Collections.Generic.IEnumerator<SharpCompress.Readers.Rar.RarReaderEntry>.get_Current" fullword ascii
      $s18 = "System.Collections.Generic.IEnumerable<SharpCompress.Archives.Tar.TarArchiveEntry>.GetEnumerator" fullword ascii
      $s19 = "System.Collections.Generic.IEnumerable<SharpCompress.Archives.Zip.ZipArchiveEntry>.GetEnumerator" fullword ascii
      $s20 = "System.Collections.Generic.IEnumerator<SharpCompress.Archives.Rar.RarArchiveEntry>.get_Current" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule sig_59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0 {
   meta:
      description = "samples - file 59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s2 = "questedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\"><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" /><" ascii
      $s3 = "PostProcessor" fullword ascii
      $s4 = "InvokeProcessor" fullword ascii
      $s5 = "LoginConfiguration" fullword ascii
      $s6 = "LoginDescriptor" fullword ascii
      $s7 = "CompareProcessor" fullword ascii
      $s8 = "LoginListener" fullword ascii
      $s9 = "ComputeProcessor" fullword ascii
      $s10 = "LoginProcessor" fullword ascii
      $s11 = "LoginComparator" fullword ascii
      $s12 = "injectb" fullword ascii
      $s13 = "LoginImporter" fullword ascii
      $s14 = "LoginConfig" fullword ascii
      $s15 = "injectinstance" fullword ascii
      $s16 = "ProcessorFilterComp" fullword ascii
      $s17 = "m_ProcessorConfiguration" fullword ascii
      $s18 = "LoginConnection" fullword ascii
      $s19 = "processConfiguration" fullword ascii
      $s20 = "SharpCompress.Templates.IdentifierConfigurationTemplate.resources" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule sig_96a6df07b7d331cd6fb9f97e7d3f2162e56f03b7f2b7cdad58193ac1d778e025 {
   meta:
      description = "samples - file 96a6df07b7d331cd6fb9f97e7d3f2162e56f03b7f2b7cdad58193ac1d778e025.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "96a6df07b7d331cd6fb9f97e7d3f2162e56f03b7f2b7cdad58193ac1d778e025"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\sfKHoHKyrt\\src\\obj\\Debug\\TypeNameNative.pdb" fullword ascii
      $s2 = "TypeNameNative.exe" fullword wide
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s4 = "496E76616C69644F6C6556617269616E7454797065457863657074696F6E" wide /* hex encoded string 'InvalidOleVariantTypeException' */
      $s5 = "32714863334D" wide /* hex encoded string '2qHc3M' */
      $s6 = "ProcessWindowItemTextChanged" fullword ascii
      $s7 = "ProcessShowIconsChanged" fullword ascii
      $s8 = "ProcessWindowItemRemoved" fullword ascii
      $s9 = "ProcessWindowItemAdded" fullword ascii
      $s10 = "ProcessEmphasizeSelectedTabChanged" fullword ascii
      $s11 = "ProcessWindowItemsCleared" fullword ascii
      $s12 = "MDIWindowManager.SystemTabsProvider.resources" fullword ascii
      $s13 = "get_RestrictedError" fullword ascii
      $s14 = "My.Computer" fullword ascii
      $s15 = "MyTemplate" fullword ascii
      $s16 = "SetAsTemporaryPanel" fullword ascii
      $s17 = "add_TempPanelDismissed" fullword ascii
      $s18 = "IsTemporaryPanel" fullword ascii
      $s19 = "m_nextWindowManagerPanel_TempPanelDismissed" fullword ascii
      $s20 = "remove_TempPanelDismissed" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3 {
   meta:
      description = "samples - file 1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\PgOLiaOwit\\src\\obj\\Debug\\ICMS.pdb" fullword ascii
      $s2 = "ICMS.exe" fullword wide
      $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s4 = "GhostComboBox_DropDownClosed" fullword ascii
      $s5 = "546F6B656E496D706572736F6E6174696F6E4C6576656C" wide /* hex encoded string 'TokenImpersonationLevel' */
      $s6 = "54466E774345" wide /* hex encoded string 'TFnwCE' */
      $s7 = "\\Hosiery.exe" fullword wide
      $s8 = "\\Terminal.exe" fullword wide
      $s9 = "get_OutputScript" fullword ascii
      $s10 = "get_InputScripts" fullword ascii
      $s11 = "get_OutputScripts" fullword ascii
      $s12 = "get_InputScript" fullword ascii
      $s13 = "get_OutputContentType" fullword ascii
      $s14 = "get_InputContentType" fullword ascii
      $s15 = "GhostComboBox_DropDown" fullword ascii
      $s16 = "get_InputContentTypes" fullword ascii
      $s17 = "get_OutputContentTypes" fullword ascii
      $s18 = "get_RestrictedError" fullword ascii
      $s19 = "get_StepVersion" fullword ascii
      $s20 = "get_ServiceFlag" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f {
   meta:
      description = "samples - file b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f"
   strings:
      $x1 = "targetTUmNewtonsoft.Json.Required, Newtonsoft.Json, Version=13.0.0.0, Culture=neutral, PublicKeyToken=30ad4fe6b2a6aeed" fullword ascii
      $x2 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii
      $x3 = "MessagesBuildInfo.config file has incorrect xml structure. Context component version will not be populated. Exception: {0}.TUrSy" ascii
      $x4 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3ajSystem.CodeDom.MemberAtt" ascii
      $x5 = "stopProcessingTUmNewtonsoft.Json.Required, Newtonsoft.Json, Version=13.0.0.0, Culture=neutral, PublicKeyToken=30ad4fe6b2a6aeed" fullword ascii
      $s6 = "get_ListProcessIdsToDump" fullword ascii
      $s7 = "get_AddedProcessDump" fullword ascii
      $s8 = "invalidateOnPrimaryIdChangeTUmNewtonsoft.Json.Required, Newtonsoft.Json, Version=13.0.0.0, Culture=neutral, PublicKeyToken=30ad4" ascii
      $s9 = "[msg=Log verbose];[msg={0}]TUrSystem.Diagnostics.Tracing.EventLevel, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=" ascii
      $s10 = "[msg=Log Error];[msg={0}]TUrSystem.Diagnostics.Tracing.EventLevel, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b7" ascii
      $s11 = "[msg=Log verbose];[msg={0}]TUrSystem.Diagnostics.Tracing.EventLevel, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=" ascii
      $s12 = "Message:Telemetry tracking was enabled. Messages are being logged.TUrSystem.Diagnostics.Tracing.EventLevel, mscorlib, Version=4." ascii
      $s13 = "MessageUNo Telemetry Configuration provided. Using the default TelemetryConfiguration.Active.TUrSystem.Diagnostics.Tracing.Event" ascii
      $s14 = "invalidateOnPrimaryIdChangeTUmNewtonsoft.Json.Required, Newtonsoft.Json, Version=13.0.0.0, Culture=neutral, PublicKeyToken=30ad4" ascii
      $s15 = "[msg=Log Error];[msg={0}]TUrSystem.Diagnostics.Tracing.EventLevel, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b7" ascii
      $s16 = "Fault Event Dump Process threw exception." fullword wide
      $s17 = "This property is obsolete. Use TelemetrySession.BucketFiltersToAddDumpsToFaults to add process dumps to fault events. They are d" ascii
      $s18 = "This property is obsolete. Use TelemetrySession.BucketFiltersToAddDumpsToFaults to add process dumps to fault events. They are d" ascii
      $s19 = "hardwareIdComponentsTUmNewtonsoft.Json.Required, Newtonsoft.Json, Version=13.0.0.0, Culture=neutral, PublicKeyToken=30ad4fe6b2a6" ascii
      $s20 = "TUuSystem.Diagnostics.Tracing.EventKeywords, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule sig_8811dde82b3c3bc28fba1619b7332ea654cb61f103f04e220e79402aa711ac37 {
   meta:
      description = "samples - file 8811dde82b3c3bc28fba1619b7332ea654cb61f103f04e220e79402aa711ac37.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8811dde82b3c3bc28fba1619b7332ea654cb61f103f04e220e79402aa711ac37"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "Client.exe" fullword wide
      $s3 = "oree.dllA" fullword ascii
      $s4 = "<GetReverseProxyByConnectionId>b__0" fullword ascii
      $s5 = "CloseMutex" fullword ascii
      $s6 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s7 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s8 = "      <!-- Windows 8 -->" fullword ascii
      $s9 = "      <!-- Windows 8.1 -->" fullword ascii
      $s10 = "      <!-- Windows Vista -->" fullword ascii
      $s11 = "      <!-- Windows 7 -->" fullword ascii
      $s12 = "      <!-- Windows 10 -->" fullword ascii
      $s13 = "remoteport" fullword ascii
      $s14 = "xClient.Core.Data" fullword ascii
      $s15 = "getbb1JO0WcWPlip9uI" fullword ascii
      $s16 = "2JEYEchg FA" fullword ascii
      $s17 = "<GetSubtypes>d__1" fullword ascii
      $s18 = "yeVfhH0kedT8PwLOgqQ" fullword ascii
      $s19 = "acheAd~x" fullword ascii
      $s20 = "lOfTpv@x>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_645168fedeed9948b5103f10d52c9adf1133358e1b1ab4ac0893dd3bb73b2df5 {
   meta:
      description = "samples - file 645168fedeed9948b5103f10d52c9adf1133358e1b1ab4ac0893dd3bb73b2df5.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "645168fedeed9948b5103f10d52c9adf1133358e1b1ab4ac0893dd3bb73b2df5"
   strings:
      $s1 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s2 = "          processorArchitecture=\"*\"" fullword ascii
      $s3 = "      processorArchitecture=\"*\"" fullword ascii
      $s4 = "  <description>Isolation Notify</description>" fullword ascii
      $s5 = "aaadddeeee" ascii
      $s6 = "A$00$0A@VCComTypeInfoHolder@ATL@@@ATL@@" fullword ascii
      $s7 = "      version=\"1.0.0.0\"" fullword ascii
      $s8 = "CDDCCCCCCC" ascii
      $s9 = "DDDDEDEEEEEB" ascii
      $s10 = "DDDCDCDECEC" ascii
      $s11 = "DDDDDDCCECCB" ascii
      $s12 = "      name=\"napstat.exe\"" fullword ascii
      $s13 = "D9d$$t " fullword ascii /* Goodware String - occured 1 times */
      $s14 = "T$`D+|$T" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "H;KXs_H" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "?KKGI<8;" fullword ascii
      $s17 = ";{Du99kDu" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "fD;'sCI" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "i(f;k(u7I" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "t%fE;0sH" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule adeeb5ab4974433126bf0c2d15234dc13fcd577217babbf0d352517ec588b7af {
   meta:
      description = "samples - file adeeb5ab4974433126bf0c2d15234dc13fcd577217babbf0d352517ec588b7af.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "adeeb5ab4974433126bf0c2d15234dc13fcd577217babbf0d352517ec588b7af"
   strings:
      $s1 = "    <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s2 = "          processorArchitecture=\"*\"" fullword ascii
      $s3 = "      processorArchitecture=\"*\"" fullword ascii
      $s4 = "  <description>Isolation Notify</description>" fullword ascii
      $s5 = "aaadddeeee" ascii
      $s6 = "A$00$0A@VCComTypeInfoHolder@ATL@@@ATL@@" fullword ascii
      $s7 = "      version=\"1.0.0.0\"" fullword ascii
      $s8 = "CDDCCCCCCC" ascii
      $s9 = "DDDDEDEEEEEB" ascii
      $s10 = "DDDCDCDECEC" ascii
      $s11 = "DDDDDDCCECCB" ascii
      $s12 = "      name=\"napstat.exe\"" fullword ascii
      $s13 = "D9d$$t " fullword ascii /* Goodware String - occured 1 times */
      $s14 = "T$`D+|$T" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "H;KXs_H" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "?KKGI<8;" fullword ascii
      $s17 = ";{Du99kDu" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "fD;'sCI" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "i(f;k(u7I" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "t%fE;0sH" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366 {
   meta:
      description = "samples - file d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */
      $s7 = "SSPICLI.DLL" fullword wide
      $s8 = "UXTheme.dll" fullword wide
      $s9 = "oleaccrc.dll" fullword wide
      $s10 = "dnsapi.DLL" fullword wide
      $s11 = "iphlpapi.DLL" fullword wide
      $s12 = "WINNSI.DLL" fullword wide
      $s13 = "sfxrar.exe" fullword ascii
      $s14 = "work.exe" fullword ascii
      $s15 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii
      $s16 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s17 = "$GETPASSWORD1:SIZE" fullword ascii
      $s18 = "$GETPASSWORD1:IDOK" fullword ascii
      $s19 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii
      $s20 = "  processorArchitecture=\"*\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252 {
   meta:
      description = "samples - file 9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */
      $s7 = "SSPICLI.DLL" fullword wide
      $s8 = "UXTheme.dll" fullword wide
      $s9 = "oleaccrc.dll" fullword wide
      $s10 = "dnsapi.DLL" fullword wide
      $s11 = "iphlpapi.DLL" fullword wide
      $s12 = "WINNSI.DLL" fullword wide
      $s13 = "sfxrar.exe" fullword ascii
      $s14 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s15 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s16 = "D:\\Projects\\WinRAR\\sfx\\setup\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii
      $s17 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s18 = "SEtUp=msiexec       /y" fullword ascii
      $s19 = "      <requestedExecutionLevel level=\"asInvoker\"           " fullword ascii
      $s20 = "  processorArchitecture=\"*\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule sig_35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7 {
   meta:
      description = "samples - file 35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7"
   strings:
      $x1 = "Setup=explorer C:\\Users\\Public\\just_build.exe" fullword ascii
      $x2 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */
      $x3 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */
      $x4 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */
      $x5 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */
      $x6 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */
      $s7 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */
      $s8 = "Path=C:\\Users\\Public" fullword ascii
      $s9 = "SSPICLI.DLL" fullword wide
      $s10 = "UXTheme.dll" fullword wide
      $s11 = "oleaccrc.dll" fullword wide
      $s12 = "dnsapi.DLL" fullword wide
      $s13 = "iphlpapi.DLL" fullword wide
      $s14 = "WINNSI.DLL" fullword wide
      $s15 = "sfxrar.exe" fullword ascii
      $s16 = "just_build.exe" fullword ascii
      $s17 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii
      $s18 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s19 = "$GETPASSWORD1:SIZE" fullword ascii
      $s20 = "$GETPASSWORD1:IDOK" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule sig_1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715 {
   meta:
      description = "samples - file 1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */
      $s7 = "SSPICLI.DLL" fullword wide
      $s8 = "UXTheme.dll" fullword wide
      $s9 = "oleaccrc.dll" fullword wide
      $s10 = "dnsapi.DLL" fullword wide
      $s11 = "iphlpapi.DLL" fullword wide
      $s12 = "WINNSI.DLL" fullword wide
      $s13 = "sfxrar.exe" fullword ascii
      $s14 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide
      $s15 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii
      $s16 = "CMT;The comment below contains SFX script commands" fullword ascii
      $s17 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s18 = "$GETPASSWORD1:SIZE" fullword ascii
      $s19 = "$GETPASSWORD1:IDOK" fullword ascii
      $s20 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      1 of ($x*) and 4 of them
}

rule b048a1bfca1c0f1a364faeef88c9decda4fa71a66e3dd3225abe70e267b0b36b {
   meta:
      description = "samples - file b048a1bfca1c0f1a364faeef88c9decda4fa71a66e3dd3225abe70e267b0b36b.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b048a1bfca1c0f1a364faeef88c9decda4fa71a66e3dd3225abe70e267b0b36b"
   strings:
      $s1 = "C:\\yuvucopupelus\\zoyu19\\corimik\\hajezugo\\loxamox.pdb" fullword ascii
      $s2 = "-kkkkk" fullword ascii /* reversed goodware string 'kkkkk-' */
      $s3 = "6e???????" fullword ascii /* hex encoded string 'n' */
      $s4 = " constructor or from DllMain." fullword ascii
      $s5 = ";(<7<@<d<" fullword ascii /* hex encoded string '}' */
      $s6 = "2*2/2:2?2]2" fullword ascii /* hex encoded string '"""' */
      $s7 = "ladutojavufu" fullword ascii
      $s8 = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk" ascii
      $s9 = "tkkkkkkkkkk" fullword ascii
      $s10 = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" fullword ascii
      $s11 = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk" fullword ascii
      $s12 = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk" ascii
      $s13 = "roronivecekuwurepup" fullword wide
      $s14 = "jisukupojawiyufacitid" fullword wide
      $s15 = "hirovorekecepozusekejoludux" fullword wide
      $s16 = "kapawafejuh" fullword wide
      $s17 = "vemonipilu" fullword wide
      $s18 = "padugebopukubafiyavajabi" fullword wide
      $s19 = "lwabizuxunecijuguyeka" fullword wide
      $s20 = ": :(:0:8:L:T:X:\\:d:l:t:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      8 of them
}

rule sig_8a09e86a04a6dbd37f88d21e450d3072d11f24ba2c2f3f724383859f89a3424c {
   meta:
      description = "samples - file 8a09e86a04a6dbd37f88d21e450d3072d11f24ba2c2f3f724383859f89a3424c.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8a09e86a04a6dbd37f88d21e450d3072d11f24ba2c2f3f724383859f89a3424c"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii
      $s3 = "ExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:s" ascii
      $s4 = "%s%S.dll" fullword wide
      $s5 = "nstall System v3.02.1</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><request" ascii
      $s6 = "-}5[\\<.f" fullword ascii /* hex encoded string '_' */
      $s7 = "CRYPTBASE" fullword ascii
      $s8 = "c76-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96" ascii
      $s9 = "PROPSYS" fullword ascii
      $s10 = "APPHELP" fullword ascii
      $s11 = "UXTHEME" fullword ascii
      $s12 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s13 = "(dp])uvloG" fullword ascii
      $s14 = "s-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1" ascii
      $s15 = "!W* ;,Pm(" fullword ascii
      $s16 = "jI[vV+ O^" fullword ascii
      $s17 = "SHFOLDER" fullword ascii /* Goodware String - occured 37 times */
      $s18 = "SeShutdownPrivilege" fullword wide /* Goodware String - occured 533 times */
      $s19 = "NullsoftInstd-" fullword ascii
      $s20 = "_zMoDeQ1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule sig_566dba1fe1103869980a78a3e18e3d62e2be44935a27c825024f94fe56d7be7b {
   meta:
      description = "samples - file 566dba1fe1103869980a78a3e18e3d62e2be44935a27c825024f94fe56d7be7b.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "566dba1fe1103869980a78a3e18e3d62e2be44935a27c825024f94fe56d7be7b"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii
      $s3 = "%s%S.dll" fullword wide
      $s4 = "nstall System v3.08</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requested" ascii
      $s5 = "ecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:sch" ascii
      $s6 = "CRYPTBASE" fullword ascii
      $s7 = "dialytic" fullword wide
      $s8 = "autogeny" fullword wide
      $s9 = "6-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4" ascii
      $s10 = "PROPSYS" fullword ascii
      $s11 = "APPHELP" fullword ascii
      $s12 = "NTMARTA" fullword ascii
      $s13 = "UXTHEME" fullword ascii
      $s14 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s15 = "microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f6" ascii
      $s16 = "67.83.92.88" fullword wide
      $s17 = "I.%k%BUZf" fullword ascii
      $s18 = "SHFOLDER" fullword ascii /* Goodware String - occured 37 times */
      $s19 = "NullsoftInst" fullword ascii /* Goodware String - occured 89 times */
      $s20 = "SeShutdownPrivilege" fullword wide /* Goodware String - occured 533 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      1 of ($x*) and 4 of them
}

rule b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26 {
   meta:
      description = "samples - file b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26"
   strings:
      $x1 = "jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
      $x2 = "jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
      $s3 = " System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3amSystem.Globalization.CultureInfo, mscorlib, V" ascii
      $s4 = "kPQM5JC0.exe" fullword wide
      $s5 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s6 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPADP" fullword ascii
      $s7 = "* labelErrorApellido" fullword wide
      $s8 = "* labelErrorNombre" fullword wide
      $s9 = " System.Globalization.CompareInfo" fullword ascii
      $s10 = "kPQM5JC0.pdb" fullword ascii
      $s11 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii
      $s12 = "get_labelErrorApellifo" fullword ascii
      $s13 = "get_VariableServices" fullword ascii
      $s14 = "get_cmdControls" fullword ascii
      $s15 = "get_cmdExit" fullword ascii
      $s16 = "get_labelErrorNombre" fullword ascii
      $s17 = "My.Computer" fullword ascii
      $s18 = "MyTemplate" fullword ascii
      $s19 = "'System.Globalization.DateTimeFormatInfo+" fullword ascii
      $s20 = "(System.Globalization.DateTimeFormatFlags" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f {
   meta:
      description = "samples - file f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f"
   strings:
      $x1 = "jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
      $x2 = "jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
      $s3 = " System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3amSystem.Globalization.CultureInfo, mscorlib, V" ascii
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s5 = "Y20Vi5Cb.exe" fullword wide
      $s6 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPADP" fullword ascii
      $s7 = "* labelErrorApellido" fullword wide
      $s8 = "* labelErrorNombre" fullword wide
      $s9 = " System.Globalization.CompareInfo" fullword ascii
      $s10 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii
      $s11 = "get_labelErrorApellifo" fullword ascii
      $s12 = "get_VariableServices" fullword ascii
      $s13 = "get_cmdControls" fullword ascii
      $s14 = "get_cmdExit" fullword ascii
      $s15 = "get_labelErrorNombre" fullword ascii
      $s16 = "My.Computer" fullword ascii
      $s17 = "MyTemplate" fullword ascii
      $s18 = "'System.Globalization.DateTimeFormatInfo+" fullword ascii
      $s19 = "(System.Globalization.DateTimeFormatFlags" fullword ascii
      $s20 = "Y20Vi5Cb.pdb" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7fbc757d {
   meta:
      description = "samples - file d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7fbc757d.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7fbc757d"
   strings:
      $s1 = "sWindowsApp1.InkBot+VB$StateMachine_15_SendTweet, WindowsApp1, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword ascii
      $s2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s3 = "My.Computer" fullword ascii
      $s4 = "MyTemplate" fullword ascii
      $s5 = "_TileTemplate" fullword ascii
      $s6 = "System.Windows.Forms.Form" fullword ascii
      $s7 = "_OAuthTokenSecret" fullword ascii
      $s8 = ".NET Framework 4.6" fullword ascii
      $s9 = "OAuthTokenSecret" fullword wide
      $s10 = "GetTypeProperty" fullword ascii
      $s11 = "GetTypes" fullword wide
      $s12 = "CredentialStore" fullword wide
      $s13 = "mainimage" fullword ascii
      $s14 = "encuesta" fullword wide
      $s15 = "My.WebServices" fullword ascii
      $s16 = "_ConsumerSecret" fullword ascii
      $s17 = "y4K9An.MyXtraGrid.Form1.resources" fullword ascii
      $s18 = "y4K9An.Resources.resources" fullword ascii
      $s19 = "m_ThreadStaticValue" fullword ascii
      $s20 = "_OAuthToken" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_6bbec1195b67c774482b5b181107f3f2ea3d81cc6056aaa75f062a250fc1e418 {
   meta:
      description = "samples - file 6bbec1195b67c774482b5b181107f3f2ea3d81cc6056aaa75f062a250fc1e418.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "6bbec1195b67c774482b5b181107f3f2ea3d81cc6056aaa75f062a250fc1e418"
   strings:
      $s1 = "Office.exe" fullword wide
      $s2 = "        <requestedExecutionLevel level='highestAvailable' uiAccess='false' />" fullword ascii
      $s3 = "LIlB.WpS" fullword ascii
      $s4 = "* reyB" fullword ascii
      $s5 = "* kOS3" fullword ascii
      $s6 = "%1}*%d%" fullword ascii
      $s7 = "\"9$e:\"" fullword ascii
      $s8 = "Xw:\"8dw" fullword ascii
      $s9 = "BDz:\"r" fullword ascii
      $s10 = "l30j.jSW" fullword ascii
      $s11 = "*H*~i:\\" fullword ascii
      $s12 = ";qErP%d-" fullword ascii
      $s13 = "\\%c%r~" fullword ascii
      $s14 = "!!!h2O" fullword ascii
      $s15 = "x{{Spy" fullword ascii
      $s16 = ":Lvxeye" fullword ascii
      $s17 = "B* (bq" fullword ascii
      $s18 = "YBOFw06" fullword ascii
      $s19 = "zp* rX" fullword ascii
      $s20 = "# d%oX" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule sig_0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc {
   meta:
      description = "samples - file 0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc"
   strings:
      $s1 = "xmscoree.dll" fullword wide
      $s2 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "@api-ms-win-core-synch-l1-2-0.dll" fullword wide
      $s5 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s6 = "operator<=>" fullword ascii
      $s7 = "operator co_await" fullword ascii
      $s8 = "<\"<+<4<D<" fullword ascii /* hex encoded string 'M' */
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = "c75c6c37b2d7a348188eddc50140787b" ascii
      $s11 = "JgLufPK0" fullword ascii
      $s12 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" fullword ascii /* Goodware String - occured 903 times */
      $s13 = "QQSVj8j@" fullword ascii
      $s14 = "__swift_1" fullword ascii
      $s15 = "__swift_2" fullword ascii
      $s16 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s17 = "RzLm3PPj7GCqeAKnehdpGabXQ2Fx8BP4aPZu" fullword ascii
      $s18 = "=&>@>E>" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "RODF0s==" fullword ascii
      $s20 = "IvOmNs==" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6 {
   meta:
      description = "samples - file 2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6"
   strings:
      $s1 = "xmscoree.dll" fullword wide
      $s2 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "@api-ms-win-core-synch-l1-2-0.dll" fullword wide
      $s5 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s6 = "operator<=>" fullword ascii
      $s7 = "operator co_await" fullword ascii
      $s8 = "U4lPQFSOMID68kHcfrPvdTU0dj7lPSLWXHNr7oOz16nhQT3ghKTcXdak0T76LQZKVIJLOGuXHYHKOYu=" fullword ascii
      $s9 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s10 = "U39CQGaCJoLhOTjagq7rdTO0YCbi7cHrd6McOmOdF7LD8jTlhJXdeeCpcZ2=" fullword ascii
      $s11 = "QQSVj8j@" fullword ascii
      $s12 = "__swift_1" fullword ascii
      $s13 = "__swift_2" fullword ascii
      $s14 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s15 = "WPWWWS" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "WWWSHSh" fullword ascii
      $s17 = "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
      $s18 = "Bapi-ms-win-core-datetime-l1-1-1" fullword wide
      $s19 = "cqVqUHutBDyzUUfc" fullword ascii
      $s20 = "UJFqUHBhJ6Lo9UHghLi=" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_5a2d1353ce17597f8c21f3e38396bb9e09b6d9bcf9ba52e0154bd0ce708634d3 {
   meta:
      description = "samples - file 5a2d1353ce17597f8c21f3e38396bb9e09b6d9bcf9ba52e0154bd0ce708634d3.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5a2d1353ce17597f8c21f3e38396bb9e09b6d9bcf9ba52e0154bd0ce708634d3"
   strings:
      $s1 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii
      $s2 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' public" ascii
      $s3 = "Simplify Notification Service.exe" fullword wide
      $s4 = "<!-- <li default> -->" fullword ascii
      $s5 = "    <!-- <include src=\"lang:shutdownDialog:time_left\"></include> -->" fullword ascii
      $s6 = "widget[type=\"password\"]," fullword ascii
      $s7 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s8 = "<!-- </div> -->" fullword ascii
      $s9 = "<!-- <i></i> -->" fullword ascii
      $s10 = "</include></button> -->" fullword ascii
      $s11 = "</include></option> -->" fullword ascii
      $s12 = "<div id=\"reportsDescription\">" fullword ascii
      $s13 = "<!-- <div class=\"caption\" style=\"display:block;\"> -->" fullword ascii
      $s14 = "</fieldset> -->" fullword ascii
      $s15 = "  <body class=\"\"><!-- dir=\"rtl\" -->" fullword ascii
      $s16 = "<include src=\"lang:description\">Dr.Web CureIt! believes these objects are not safe</include>" fullword ascii
      $s17 = "/* dropdown combobox */" fullword ascii
      $s18 = "/* widget { color:windowtext; } */" fullword ascii
      $s19 = "<div><button tabindex=\"103\" type=\"button\" name=\"add\" id=\"add\" disabled><include src=\"lang:dialog_button:add\">Add</incl" ascii
      $s20 = "              <!-- HTMLayout bug: that's why we need inner table -->" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule ebb35d31b8c44c163ecaadef47d7f6249cc1d2c654fa5afb1011ea1527fea927 {
   meta:
      description = "samples - file ebb35d31b8c44c163ecaadef47d7f6249cc1d2c654fa5afb1011ea1527fea927.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "ebb35d31b8c44c163ecaadef47d7f6249cc1d2c654fa5afb1011ea1527fea927"
   strings:
      $s1 = "0cd0334d-7d49-4e03-b9f8-fb1eaa0c92b4.exe" fullword wide
      $s2 = "lpdwProcessID" fullword ascii
      $s3 = "processAccess" fullword ascii
      $s4 = "get_hostmask" fullword ascii
      $s5 = "get_username" fullword ascii
      $s6 = "<password>k__BackingField" fullword ascii
      $s7 = "GetPrivateProfileString" fullword ascii
      $s8 = "passwordVaultPtr" fullword ascii
      $s9 = "get_GuidMasterKey" fullword ascii
      $s10 = "get_hoster" fullword ascii
      $s11 = "com.apple.Safari" fullword ascii
      $s12 = "VaultGetItem_WIN7" fullword ascii
      $s13 = "VaultGetItem_WIN8" fullword ascii
      $s14 = "set_hostmask" fullword ascii
      $s15 = "5#>&\"\"0" fullword ascii /* hex encoded string 'P' */
      $s16 = "get_LastAccessed" fullword ascii
      $s17 = "<hoster>k__BackingField" fullword ascii
      $s18 = "<hostmask>k__BackingField" fullword ascii
      $s19 = "get_StoreSize" fullword ascii
      $s20 = "get_StorageSize" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a {
   meta:
      description = "samples - file a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\Client\\Temp\\HHPXBylZVC\\src\\obj\\Debug\\VolatileBool.pdb" fullword ascii
      $s2 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD_c7" fullword ascii
      $s3 = "VolatileBool.exe" fullword wide
      $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s5 = "525341506172616D6574657273" wide /* hex encoded string 'RSAParameters' */
      $s6 = "4D414C465731" wide /* hex encoded string 'MALFW1' */
      $s7 = "FiltreProcessor`1" fullword ascii
      $s8 = "get_RestrictedError" fullword ascii
      $s9 = "My.Computer" fullword ascii
      $s10 = "MyTemplate" fullword ascii
      $s11 = "System.Windows.Forms.Form" fullword ascii
      $s12 = "/8m]!!!" fullword ascii
      $s13 = "get_ValueEnumerator" fullword ascii
      $s14 = "_GetElementValeur" fullword ascii
      $s15 = "get_RSAParameters" fullword ascii
      $s16 = "get_SqlExpression" fullword ascii
      $s17 = "getValeurMethode" fullword ascii
      $s18 = "_GetValeurMethode" fullword ascii
      $s19 = "GetValeurDelegate" fullword ascii
      $s20 = "get_MainDomains" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38 {
   meta:
      description = "samples - file 7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38"
   strings:
      $s1 = "Idiomatic.exe" fullword wide
      $s2 = "zocupixinimapok naludatugecuco logenenoyihuyo" fullword ascii
      $s3 = "!!!hhhhhhhhhh" fullword ascii
      $s4 = "TJaxowofa rupek tibey tujibihagom pagije ceyeparihigopi hezosukirihur bemediwixocezop" fullword wide
      $s5 = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" fullword ascii
      $s6 = "E**jjjjjjjjjj* ww" fullword ascii
      $s7 = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" fullword ascii
      $s8 = "nawutizefekogayur" fullword wide
      $s9 = "jakidiruwazunural" fullword wide
      $s10 = "wfogado" fullword wide
      $s11 = "patogep" fullword wide
      $s12 = "goxobabewevamadufewamefayiyawahi" fullword wide
      $s13 = "nubelopobupayuxoketuwigirazivu" fullword wide
      $s14 = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK" ascii
      $s15 = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK" ascii
      $s16 = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK" fullword ascii
      $s17 = "KKKKKKKKKKKKKKKKKKKK" fullword ascii
      $s18 = "KKKKKKKKKKKKKKKKKKKKK" fullword ascii
      $s19 = "KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK" fullword ascii
      $s20 = "BCYCCCCC" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_091245bf789aabbefd2a412d39aeddec596c8b71aa93fdb4eb1c7b7d38ed3f90 {
   meta:
      description = "samples - file 091245bf789aabbefd2a412d39aeddec596c8b71aa93fdb4eb1c7b7d38ed3f90.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "091245bf789aabbefd2a412d39aeddec596c8b71aa93fdb4eb1c7b7d38ed3f90"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "a7HFd4ZXk71kM7eVqG9.SPrHmRZ7qgvqwqISbgw+u8GXYpZNmOw8O221tpv+TlJ6lWZEmgnPapr1J1k`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii
      $s3 = "a7HFd4ZXk71kM7eVqG9.SPrHmRZ7qgvqwqISbgw+u8GXYpZNmOw8O221tpv+TlJ6lWZEmgnPapr1J1k`1[[System.Object, mscorlib, Version=4.0.0.0, Cul" ascii
      $s4 = "a1sscVxISg" fullword ascii /* base64 encoded string 'k[,q\HJ' */
      $s5 = "SVoyfTdZRv" fullword ascii /* base64 encoded string 'IZ2}7YF' */
      $s6 = "cFxEZFdWNl" fullword ascii /* base64 encoded string 'p\DdWV6' */
      $s7 = "cltUP25JF" fullword ascii /* base64 encoded string 'r[T?nI' */
      $s8 = "ture=neutral, PublicKeyToken=b77a5c561934e089]][]" fullword ascii
      $s9 = "iWMZEyeGLkd0liu1U7J" fullword ascii
      $s10 = "PA3Ytu0FTPDEy9RVHav" fullword ascii
      $s11 = "ms5D6H57VkIrCoCYUMJ" fullword ascii
      $s12 = "yatgXCg0POIDllJtFBh" fullword ascii
      $s13 = "GfsdXLp0c0" fullword ascii
      $s14 = "aZahbTIBXIp7F35geTt" fullword ascii
      $s15 = "D2VxkfXNUdUiicEyeUd" fullword ascii
      $s16 = "hiRC37m4xF" fullword ascii
      $s17 = "BRDdk7GPY2fJ9OCFtpe" fullword ascii
      $s18 = "nOtlhCBA7X4G2LOGRyk" fullword ascii
      $s19 = "V668JTmORPAnHLogrT5" fullword ascii
      $s20 = "v7kw7SPYsG9FYKJ6eAZ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b {
   meta:
      description = "samples - file 23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "C:\\A10\\0b90ck742m0g\\output.pdb" fullword ascii
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s4 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s5 = "`template-parameter-" fullword ascii
      $s6 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii
      $s7 = "AppPolicyGetWindowingModel" fullword ascii
      $s8 = "operator<=>" fullword ascii
      $s9 = "operator co_await" fullword ascii
      $s10 = "=,>3>:>A>" fullword ascii /* hex encoded string ':' */
      $s11 = "nullptr" fullword ascii
      $s12 = "regex_error(error_stack): There was insufficient memory to determine whether the regular expression could match the specified ch" ascii
      $s13 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s14 = " noexcept" fullword ascii
      $s15 = " volatile" fullword ascii
      $s16 = "QQSVj8j@" fullword ascii
      $s17 = "__swift_1" fullword ascii
      $s18 = "__swift_3" fullword ascii
      $s19 = "__swift_2" fullword ascii
      $s20 = "char8_t" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_7ed9f4f6c6f6919e85b0f7b46ab95b356ca7702a1a3d415124753b4c77b12541 {
   meta:
      description = "samples - file 7ed9f4f6c6f6919e85b0f7b46ab95b356ca7702a1a3d415124753b4c77b12541.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7ed9f4f6c6f6919e85b0f7b46ab95b356ca7702a1a3d415124753b4c77b12541"
   strings:
      $s1 = "socks64.dll" fullword ascii
      $s2 = "Zws2_32.dll" fullword ascii
      $s3 = "rundll" fullword ascii
      $s4 = "GXjn.xJr" fullword ascii
      $s5 = "* %@$%!" fullword ascii
      $s6 = "b D=LNFtpx^7" fullword ascii
      $s7 = "* +3$Sc" fullword ascii
      $s8 = "TQdE2v /H" fullword ascii
      $s9 = "2x:\\Uk{" fullword ascii
      $s10 = "ucv.MNQ" fullword ascii
      $s11 = "D3R.iMK" fullword ascii
      $s12 = "fC6.qQb" fullword ascii
      $s13 = "p:\"z@=U" fullword ascii
      $s14 = "MCG.OAC" fullword ascii
      $s15 = "OUHA:\\-`xuC" fullword ascii
      $s16 = "- X@IG" fullword ascii
      $s17 = "RuVu* " fullword ascii
      $s18 = "5v- 0S1" fullword ascii
      $s19 = "|FrF+ " fullword ascii
      $s20 = "vnH /C" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      8 of them
}

rule sig_0c9d6d9180321e740f823f4a5d5d356cefdf7211d264401a6ccc61fa3cd6728f {
   meta:
      description = "samples - file 0c9d6d9180321e740f823f4a5d5d356cefdf7211d264401a6ccc61fa3cd6728f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "0c9d6d9180321e740f823f4a5d5d356cefdf7211d264401a6ccc61fa3cd6728f"
   strings:
      $x1 = "BJUvqhFOueBFfEGlgflXGQ2dpz8jg7yVgNx/nctv0ajbnJ6orRw649AuiZrLJzLBjbNT7eHkg2+41wEl4M75dFpAbKygfcUyFBf6Q1lyvw2zKsRmaaIakCKifzqdKb3T" wide
      $s2 = "ObjectManag.exe" fullword wide
      $s3 = "417574686F72697A6174696F6E5275" wide /* hex encoded string 'AuthorizationRu' */
      $s4 = "5834684349" wide /* hex encoded string 'X4hCI' */
      $s5 = "txtLogin_Click" fullword ascii
      $s6 = "get_AuthorizationRu" fullword ascii
      $s7 = "LOGIN|" fullword wide
      $s8 = "get_HeadImageIndex" fullword ascii
      $s9 = "<HeadImageIndex>k__BackingField" fullword ascii
      $s10 = "set_HeadImageIndex" fullword ascii
      $s11 = "picHeadImage_Click" fullword ascii
      $s12 = "get_ParamXArray" fullword ascii
      $s13 = "get_NickName" fullword ascii
      $s14 = "get_Shuoshuo" fullword ascii
      $s15 = "get_ChangeX" fullword ascii
      $s16 = "picHeadImage" fullword wide
      $s17 = "get_chatHistory" fullword ascii
      $s18 = "get_ParamXGroup" fullword ascii
      $s19 = "LeftPosiiton" fullword ascii
      $s20 = "getMyIP" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2 {
   meta:
      description = "samples - file 2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2"
   strings:
      $x1 = "C:\\Users\\root\\Desktop\\stubpublicf1\\x64\\Debug\\stubpublicf1.pdb" fullword ascii
      $s2 = "weel.exe" fullword wide
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = " http://www.microsoft.com/windows0" fullword ascii
      $s5 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_type_info.cpp" fullword ascii
      $s6 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii
      $s7 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide
      $s8 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide
      $s9 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide
      $s10 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s11 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii
      $s12 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii
      $s13 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532\\include\\vector" fullword wide
      $s14 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532\\include\\xmemory" fullword wide
      $s15 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.36.32532\\include\\xstring" fullword wide
      $s16 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s17 = "string subscript out of range" fullword ascii
      $s18 = "vector subscript out of range" fullword ascii
      $s19 = "minkernel\\crts\\ucrt\\src\\appcrt\\heap\\new_handler.cpp" fullword wide
      $s20 = "minkernel\\crts\\ucrt\\src\\appcrt\\internal\\win_policies.cpp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      1 of ($x*) and 4 of them
}

rule sig_8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f {
   meta:
      description = "samples - file 8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f"
   strings:
      $x1 = "powershell -Command \"Start-Process -FilePath 'C:\\Windows \\System32\\ComputerDefaults.exe' -Verb RunAs\"" fullword ascii
      $x2 = "\\\\?\\C:\\Windows \\System32\\profapi.dll" fullword ascii
      $x3 = "\\\\?\\C:\\Windows \\System32\\ComputerDefaults.exe" fullword ascii
      $s4 = "D:\\1my\\1main_proj\\loader_cpp\\x64\\Release\\loader_cpp.pdb" fullword ascii
      $s5 = "ComputerDefaults.exe" fullword ascii
      $s6 = "powershell New-Item '\\\\?\\C:\\Windows \\System32' -ItemType Directory" fullword ascii
      $s7 = "https://sh4590209.c.had.su/files/DLL1.dll" fullword ascii
      $s8 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s9 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii
      $s10 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide
      $s11 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide
      $s12 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide
      $s13 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s14 = "\\sys.exe" fullword ascii
      $s15 = "D:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.35.32215\\include\\xmemory" fullword wide
      $s16 = "https://sh4590209.c.had.su/files/ComputerDefaults.xfx" fullword ascii
      $s17 = "powershell Move-Item -Path '" fullword ascii
      $s18 = " strcpy_s(szUserMessage, 4096, \"_CrtDbgReport: String too long or IO Error\")" fullword wide
      $s19 = "minkernel\\crts\\ucrt\\src\\appcrt\\internal\\win_policies.cpp" fullword wide
      $s20 = "minkernel\\crts\\ucrt\\src\\appcrt\\lowio\\close.cpp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072 {
   meta:
      description = "samples - file a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii
      $s3 = "overmodigstes crossest.exe" fullword wide
      $s4 = "nstall System v3.05</description><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requested" ascii
      $s5 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii
      $s6 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii
      $s7 = "ecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:sch" ascii
      $s8 = "CRYPTBASE" fullword ascii
      $s9 = "6-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4" ascii
      $s10 = "PROPSYS" fullword ascii
      $s11 = "APPHELP" fullword ascii
      $s12 = "NTMARTA" fullword ascii
      $s13 = "UXTHEME" fullword ascii
      $s14 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s15 = "microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f6" ascii
      $s16 = "fngselsprsten supersede unpacifiedly" fullword wide
      $s17 = "XKUgYE6" fullword ascii
      $s18 = "d?W0 -" fullword ascii
      $s19 = "\\VAncX%H]" fullword ascii
      $s20 = "C.0+>%k%" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule c0de3820d44c7aebc56f12be217cab5c5b758344750e73e1288f42e0f373f038 {
   meta:
      description = "samples - file c0de3820d44c7aebc56f12be217cab5c5b758344750e73e1288f42e0f373f038.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "c0de3820d44c7aebc56f12be217cab5c5b758344750e73e1288f42e0f373f038"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $x2 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKeyToken=\"6595b64144" ascii
      $s3 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s4 = "requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivile" ascii
      $s5 = "ngklr.exe" fullword ascii
      $s6 = "ZDovZmlsZTEudHh0" fullword ascii /* base64 encoded string 'd:/file1.txt' */
      $s7 = "SW5kaWEgU3RhbmRhcmQgVGltZQ==" fullword ascii /* base64 encoded string 'India Standard Time' */
      $s8 = "MiA9IHswfQ==" fullword ascii /* base64 encoded string '2 = {0}' */
      $s9 = "MSA9IHswfQ==" fullword ascii /* base64 encoded string '1 = {0}' */
      $s10 = "U1c1MmIydGw=" fullword ascii /* base64 encoded string 'SW52b2tl' */
      $s11 = "ZG1KakxtVjRaUT09" fullword ascii /* base64 encoded string 'dmJjLmV4ZQ==' */
      $s12 = "VGljayBDb3VudDog" fullword ascii /* base64 encoded string 'Tick Count: ' */
      $s13 = "RHluYW1pY0RsbEludm9rZVR5cGU=" fullword ascii /* base64 encoded string 'DynamicDllInvokeType' */
      $s14 = "VW1WemRXMWxWR2h5WldGaw==" fullword ascii /* base64 encoded string 'UmVzdW1lVGhyZWFk' */
      $s15 = "SW5kaWEgU3RhbmRhcmQgVGltZTog" fullword ascii /* base64 encoded string 'India Standard Time: ' */
      $s16 = "aHR0cDpkb3RuZXRwZXJscy1jb20=" fullword ascii /* base64 encoded string 'http:dotnetperls-com' */
      $s17 = "CreateGetStringDelegate" fullword ascii
      $s18 = "+.+3+4+5+:~2" fullword ascii /* hex encoded string '4R' */
      $s19 = "[#4>^\"%C" fullword ascii /* hex encoded string 'L' */
      $s20 = "NEYe+3~" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c {
   meta:
      description = "samples - file b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c"
   strings:
      $s1 = "Idiomatic.exe" fullword wide
      $s2 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s3 = "sqpzzpzzpzzpzzpzzpzzpzzz" fullword ascii
      $s4 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s5 = "yyyyyyyyyyyyy?" fullword ascii
      $s6 = "WWEyyyyyyyyy" fullword ascii
      $s7 = "zG -an" fullword ascii
      $s8 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s9 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s10 = "R%YOAO}p%" fullword ascii
      $s11 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAAZ\"" fullword ascii
      $s12 = "vvvvvvvvvvvX(+" fullword ascii
      $s13 = "ITMY!D" fullword ascii
      $s14 = "EEEEEEy" fullword ascii
      $s15 = "oFInL6|" fullword ascii
      $s16 = "rtTyB?<t" fullword ascii
      $s17 = "tttttt<<<" fullword ascii
      $s18 = "/99AAAAAAAAAAAAAAAAA" fullword ascii
      $s19 = "sssssssssssfsfsffff{k" fullword ascii
      $s20 = "99AAAAAAAAAAAAAAAAA" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161 {
   meta:
      description = "samples - file e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161"
   strings:
      $s1 = "Idiomatic.exe" fullword wide
      $s2 = "~}}z||}" fullword ascii /* reversed goodware string '}||z}}~' */
      $s3 = "}~~~}}" fullword ascii /* reversed goodware string '}}~~~}' */
      $s4 = "|{}}}}" fullword ascii /* reversed goodware string '}}}}{|' */
      $s5 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s6 = "sqpzzpzzpzzpzzpzzpzzpzzz" fullword ascii
      $s7 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s8 = "yyyyyyyyyyyyy?" fullword ascii
      $s9 = "WWEyyyyyyyyy" fullword ascii
      $s10 = "CjUmuTi5" fullword ascii
      $s11 = "tJLTU59" fullword ascii
      $s12 = ";* 7_t" fullword ascii
      $s13 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s14 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s15 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAAZ\"" fullword ascii
      $s16 = "vvvvvvvvvvvX(+" fullword ascii
      $s17 = "EEEEEEy" fullword ascii
      $s18 = "rtTyB?<t" fullword ascii
      $s19 = "tttttt<<<" fullword ascii
      $s20 = "/99AAAAAAAAAAAAAAAAA" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779 {
   meta:
      description = "samples - file 215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779"
   strings:
      $s1 = "Idiomatic.exe" fullword wide
      $s2 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s3 = "sqpzzpzzpzzpzzpzzpzzpzzz" fullword ascii
      $s4 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s5 = "yyyyyyyyyyyyy?" fullword ascii
      $s6 = "WWEyyyyyyyyy" fullword ascii
      $s7 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s8 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s9 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAAZ\"" fullword ascii
      $s10 = "vvvvvvvvvvvX(+" fullword ascii
      $s11 = "EEEEEEy" fullword ascii
      $s12 = "rtTyB?<t" fullword ascii
      $s13 = "tttttt<<<" fullword ascii
      $s14 = "/99AAAAAAAAAAAAAAAAA" fullword ascii
      $s15 = "sssssssssssfsfsffff{k" fullword ascii
      $s16 = "99AAAAAAAAAAAAAAAAA" ascii
      $s17 = "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{TTTTTTTTTTTTTTTTW" fullword ascii
      $s18 = "sssssfsssss{k" fullword ascii
      $s19 = "Tyr<?tEWEWWWWWyT?<?By" fullword ascii
      $s20 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAA" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241 {
   meta:
      description = "samples - file 02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241"
   strings:
      $s1 = "Idiomatic.exe" fullword wide
      $s2 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s3 = "sqpzzpzzpzzpzzpzzpzzpzzz" fullword ascii
      $s4 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s5 = "yyyyyyyyyyyyy?" fullword ascii
      $s6 = "WWEyyyyyyyyy" fullword ascii
      $s7 = "FP\\WzxB:\\" fullword ascii
      $s8 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAAZ\"" fullword ascii
      $s9 = "vvvvvvvvvvvX(+" fullword ascii
      $s10 = "EEEEEEy" fullword ascii
      $s11 = "rtTyB?<t" fullword ascii
      $s12 = "tttttt<<<" fullword ascii
      $s13 = "/99AAAAAAAAAAAAAAAAA" fullword ascii
      $s14 = "sssssssssssfsfsffff{k" fullword ascii
      $s15 = "99AAAAAAAAAAAAAAAAA" ascii
      $s16 = "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{TTTTTTTTTTTTTTTTW" fullword ascii
      $s17 = "sssssfsssss{k" fullword ascii
      $s18 = "Tyr<?tEWEWWWWWyT?<?By" fullword ascii
      $s19 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAA" ascii
      $s20 = " ssssssss%" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be {
   meta:
      description = "samples - file fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be"
   strings:
      $s1 = "Idiomatic.exe" fullword wide
      $s2 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s3 = "sqpzzpzzpzzpzzpzzpzzpzzz" fullword ascii
      $s4 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s5 = "yyyyyyyyyyyyy?" fullword ascii
      $s6 = "WWEyyyyyyyyy" fullword ascii
      $s7 = "3}W* \"" fullword ascii
      $s8 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s9 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s10 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAAZ\"" fullword ascii
      $s11 = "vvvvvvvvvvvX(+" fullword ascii
      $s12 = "EEEEEEy" fullword ascii
      $s13 = "rtTyB?<t" fullword ascii
      $s14 = "tttttt<<<" fullword ascii
      $s15 = "/99AAAAAAAAAAAAAAAAA" fullword ascii
      $s16 = "sssssssssssfsfsffff{k" fullword ascii
      $s17 = "99AAAAAAAAAAAAAAAAA" ascii
      $s18 = "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{TTTTTTTTTTTTTTTTW" fullword ascii
      $s19 = "sssssfsssss{k" fullword ascii
      $s20 = "Tyr<?tEWEWWWWWyT?<?By" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218 {
   meta:
      description = "samples - file 8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218"
   strings:
      $s1 = "Idiomatic.exe" fullword wide
      $s2 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s3 = "sqpzzpzzpzzpzzpzzpzzpzzz" fullword ascii
      $s4 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s5 = "yyyyyyyyyyyyy?" fullword ascii
      $s6 = "WWEyyyyyyyyy" fullword ascii
      $s7 = "\\m%l-$" fullword ascii
      $s8 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s9 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s10 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAAZ\"" fullword ascii
      $s11 = "vvvvvvvvvvvX(+" fullword ascii
      $s12 = "EEEEEEy" fullword ascii
      $s13 = "rtTyB?<t" fullword ascii
      $s14 = "tttttt<<<" fullword ascii
      $s15 = "/99AAAAAAAAAAAAAAAAA" fullword ascii
      $s16 = "sssssssssssfsfsffff{k" fullword ascii
      $s17 = "99AAAAAAAAAAAAAAAAA" ascii
      $s18 = "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{TTTTTTTTTTTTTTTTW" fullword ascii
      $s19 = "sssssfsssss{k" fullword ascii
      $s20 = "Tyr<?tEWEWWWWWyT?<?By" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d {
   meta:
      description = "samples - file 60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d"
   strings:
      $s1 = "Idiomatic.exe" fullword wide
      $s2 = "~{{~~~" fullword ascii /* reversed goodware string '~~~{{~' */
      $s3 = "||z|||" fullword ascii /* reversed goodware string '|||z||' */
      $s4 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s5 = "sqpzzpzzpzzpzzpzzpzzpzzz" fullword ascii
      $s6 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s7 = "yyyyyyyyyyyyy?" fullword ascii
      $s8 = "WWEyyyyyyyyy" fullword ascii
      $s9 = "r),H* J" fullword ascii
      $s10 = "L\\\\r@* " fullword ascii
      $s11 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s12 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s13 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAAZ\"" fullword ascii
      $s14 = "vvvvvvvvvvvX(+" fullword ascii
      $s15 = "EEEEEEy" fullword ascii
      $s16 = "rtTyB?<t" fullword ascii
      $s17 = "tttttt<<<" fullword ascii
      $s18 = "/99AAAAAAAAAAAAAAAAA" fullword ascii
      $s19 = "sssssssssssfsfsffff{k" fullword ascii
      $s20 = "99AAAAAAAAAAAAAAAAA" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule sig_0f04730f576ba9c455a7c3f03774cb9823210e728fac4674cf9f5d147a0149ef {
   meta:
      description = "samples - file 0f04730f576ba9c455a7c3f03774cb9823210e728fac4674cf9f5d147a0149ef.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "0f04730f576ba9c455a7c3f03774cb9823210e728fac4674cf9f5d147a0149ef"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $x2 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKeyToken=\"6595b64144" ascii
      $s3 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s4 = "requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivile" ascii
      $s5 = "mAmFrSbe.exe" fullword ascii
      $s6 = "ZDovZmlsZTEudHh0" fullword ascii /* base64 encoded string 'd:/file1.txt' */
      $s7 = "SW5kaWEgU3RhbmRhcmQgVGltZQ==" fullword ascii /* base64 encoded string 'India Standard Time' */
      $s8 = "MiA9IHswfQ==" fullword ascii /* base64 encoded string '2 = {0}' */
      $s9 = "MSA9IHswfQ==" fullword ascii /* base64 encoded string '1 = {0}' */
      $s10 = "U1c1MmIydGw=" fullword ascii /* base64 encoded string 'SW52b2tl' */
      $s11 = "ZG1KakxtVjRaUT09" fullword ascii /* base64 encoded string 'dmJjLmV4ZQ==' */
      $s12 = "VGljayBDb3VudDog" fullword ascii /* base64 encoded string 'Tick Count: ' */
      $s13 = "RHluYW1pY0RsbEludm9rZVR5cGU=" fullword ascii /* base64 encoded string 'DynamicDllInvokeType' */
      $s14 = "VW1WemRXMWxWR2h5WldGaw==" fullword ascii /* base64 encoded string 'UmVzdW1lVGhyZWFk' */
      $s15 = "ZGRkZGRkZGRkZA==" fullword ascii /* base64 encoded string 'dddddddddd' */
      $s16 = "SW5kaWEgU3RhbmRhcmQgVGltZTog" fullword ascii /* base64 encoded string 'India Standard Time: ' */
      $s17 = "aHR0cDpkb3RuZXRwZXJscy1jb20=" fullword ascii /* base64 encoded string 'http:dotnetperls-com' */
      $s18 = "CreateGetStringDelegate" fullword ascii
      $s19 = "+.+3+4+5+:~2" fullword ascii /* hex encoded string '4R' */
      $s20 = "gdsadffjfagg" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule sig_2a22d4d82cd5d187ce6df806f22f93f8dd83619e91595c34332286bbcc4ac7ce {
   meta:
      description = "samples - file 2a22d4d82cd5d187ce6df806f22f93f8dd83619e91595c34332286bbcc4ac7ce.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "2a22d4d82cd5d187ce6df806f22f93f8dd83619e91595c34332286bbcc4ac7ce"
   strings:
      $s1 = "PortScanner.exe" fullword wide
      $s2 = ":PortScanner.ScannerManagerSingleton+<ExecuteOnceAsync>d__8" fullword ascii
      $s3 = ";PortScanner.ScannerManagerSingleton+<ExecuteRangeAsync>d__9" fullword ascii
      $s4 = "ExecuteRangeAsync" fullword ascii
      $s5 = "<ExecuteOnceAsync>d__8" fullword ascii
      $s6 = "ExecuteOnceAsync" fullword ascii
      $s7 = "<ExecuteRangeAsync>d__9" fullword ascii
      $s8 = "Connection Error" fullword wide
      $s9 = "ExecuteOnceCallback" fullword ascii
      $s10 = "GetSaveFileDialog" fullword ascii
      $s11 = "ExecuteOnceAsyncCallback" fullword ascii
      $s12 = "ConfigureSaveFileDialog" fullword ascii
      $s13 = "WriteResPassword" fullword ascii
      $s14 = "xlTemplate8" fullword ascii
      $s15 = "GetReportType" fullword ascii
      $s16 = "Port Scanning Report" fullword wide
      $s17 = "PortScanner.Properties.Resources.resources" fullword ascii
      $s18 = "xlTemplate" fullword ascii
      $s19 = "PortScanner.Reporting" fullword ascii
      $s20 = "xlOpenXMLTemplateMacroEnabled" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553 {
   meta:
      description = "samples - file fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553"
   strings:
      $s1 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii
      $s3 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s5 = "      <!-- Windows 8 -->" fullword ascii
      $s6 = "      <!-- Windows 8.1 -->" fullword ascii
      $s7 = "      <!-- Windows Vista -->" fullword ascii
      $s8 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii
      $s9 = "      <longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii
      $s10 = "      <!-- Windows 7 -->" fullword ascii
      $s11 = "      <!-- Windows 10 -->" fullword ascii
      $s12 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s13 = "             requestedExecutionLevel node with one of the following." fullword ascii
      $s14 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii
      $s15 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii
      $s16 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii
      $s17 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii
      $s18 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" />" fullword ascii
      $s19 = "S/dump" fullword ascii
      $s20 = "          processorArchitecture=\"*\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

rule sig_93e080fc54f12414da2606f38855227f8e90bb50345a3bbd082395ee359bfc4d {
   meta:
      description = "samples - file 93e080fc54f12414da2606f38855227f8e90bb50345a3bbd082395ee359bfc4d.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "93e080fc54f12414da2606f38855227f8e90bb50345a3bbd082395ee359bfc4d"
   strings:
      $s1 = "Doc-45678.exe" fullword wide
      $s2 = "0307dff35dc84d6181126686cce52f64.resources" fullword ascii
      $s3 = "ConfuserEx v1.0.0" fullword ascii
      $s4 = "  -2oH" fullword ascii
      $s5 = "B\\`+ (" fullword ascii
      $s6 = "Debugger" fullword ascii /* Goodware String - occured 244 times */
      $s7 = "Reverse" fullword ascii /* Goodware String - occured 338 times */
      $s8 = "Module" fullword ascii /* Goodware String - occured 856 times */
      $s9 = "/aDDslVa@1" fullword ascii
      $s10 = "ExOJ'\\o" fullword ascii
      $s11 = "raTN6:P" fullword ascii
      $s12 = "HGWQZJSBJ2HJT" fullword wide
      $s13 = "oJDldFi" fullword ascii
      $s14 = "kqyS.if" fullword ascii
      $s15 = "BNEG$\"" fullword ascii
      $s16 = "krCS-se" fullword ascii
      $s17 = "WKOD51YANK5" fullword wide
      $s18 = "@ypLKy!~" fullword ascii
      $s19 = "dJqV#Ur\\Q" fullword ascii
      $s20 = "RQFy6/h" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      8 of them
}

rule b2347e804c9462b266fcd04d68ffb143cf0b1781917cc0477ea4e7af18bb7d81 {
   meta:
      description = "samples - file b2347e804c9462b266fcd04d68ffb143cf0b1781917cc0477ea4e7af18bb7d81.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b2347e804c9462b266fcd04d68ffb143cf0b1781917cc0477ea4e7af18bb7d81"
   strings:
      $s1 = "UtyYlK.exe" fullword wide
      $s2 = "7A4C5A76746C" wide /* hex encoded string 'zLZvtl' */
      $s3 = "UtyYlK.pdb" fullword ascii
      $s4 = "get_question" fullword ascii
      $s5 = "getBestFeature" fullword ascii
      $s6 = "get_possibleAnswers" fullword ascii
      $s7 = "get_answers" fullword ascii
      $s8 = "DecisionTreeSimulation.Properties.Resources.resources" fullword ascii
      $s9 = "DecisionTreeSimulation.Main.resources" fullword ascii
      $s10 = "DecisionTreeSimulation.Properties" fullword ascii
      $s11 = "computeFeatureVectors" fullword ascii
      $s12 = "This clause has already existed." fullword wide
      $s13 = "DecisionTreeSimulation.Properties.Resources" fullword wide
      $s14 = "ksdllV" fullword ascii
      $s15 = "get_zLZvtl" fullword ascii
      $s16 = "\\vdhT\"j" fullword ascii
      $s17 = "fzntab" fullword ascii
      $s18 = "# #<L{" fullword ascii
      $s19 = "wFZ+ G" fullword ascii
      $s20 = "FIrwRb9" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule c92819a5b69535e455893801e3ceabc29f5659a213ff93d4891b36c8af740059 {
   meta:
      description = "samples - file c92819a5b69535e455893801e3ceabc29f5659a213ff93d4891b36c8af740059.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "c92819a5b69535e455893801e3ceabc29f5659a213ff93d4891b36c8af740059"
   strings:
      $s1 = "jbIC.exe" fullword wide
      $s2 = "keyRememberPassword" fullword ascii
      $s3 = "Remember.Password" fullword wide
      $s4 = "jbIC.pdb" fullword ascii
      $s5 = "readTmp" fullword ascii
      $s6 = "delete from Tmp where [key] = N'" fullword wide
      $s7 = "select value from Tmp where [key] = N'" fullword wide
      $s8 = "get_Message3" fullword ascii
      $s9 = "get_Message2" fullword ascii
      $s10 = "get_Message1" fullword ascii
      $s11 = "dataGrid_CellContentClick" fullword ascii
      $s12 = "get_Message4" fullword ascii
      $s13 = "fnfcmbf" fullword ascii
      $s14 = "SELECT * FROM QLNV" fullword wide
      $s15 = "txtPass" fullword wide
      $s16 = "keyRememberId" fullword ascii
      $s17 = "QLNS.FormSua.resources" fullword ascii
      $s18 = "QLNS.Properties" fullword ascii
      $s19 = "saveTmp" fullword ascii
      $s20 = "txtPass_TextChanged" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_5dc5d1c2c2615331ea899d3c56e681d5ae4098887efb634d23ece74a29846623 {
   meta:
      description = "samples - file 5dc5d1c2c2615331ea899d3c56e681d5ae4098887efb634d23ece74a29846623.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5dc5d1c2c2615331ea899d3c56e681d5ae4098887efb634d23ece74a29846623"
   strings:
      $x1 = "Qicvz8CmQyEqWXAnjyiR6ysqbjlypKR85IDoDd5lQs5DpvGKva8y4FSATyRspMMinlOjy6uil2+Vsxy0yO/BFhS3QUDl2wUwdQgZ9xJkcjqfDjTUG9Igpzmc1HykezWz" wide
      $s2 = "SeededGrow2d.exe" fullword wide
      $s3 = "D:\\VTKproj\\FF2TEST\\test1.bmp" fullword wide
      $s4 = "D:\\VTKproj\\FF2TEST\\test2.bmp" fullword wide
      $s5 = "D:\\VTKproj\\FF2TEST\\test3.bmp" fullword wide
      $s6 = "*******************************************" fullword wide /* reversed goodware string '*******************************************' */
      $s7 = "GetSampleTest1" fullword ascii
      $s8 = "GetSampleTest3" fullword ascii
      $s9 = "GetSampleTest2" fullword ascii
      $s10 = "GetSampleTest5" fullword ascii
      $s11 = "GetSampleTest4" fullword ascii
      $s12 = "GetSampleTest6" fullword ascii
      $s13 = "ExcuteFloodFill_Queue" fullword ascii
      $s14 = "TestFloodFill" fullword ascii
      $s15 = "FloodFill2d_T" fullword ascii
      $s16 = "action_get_count" fullword ascii
      $s17 = "ExcuteFloodFill_Stack" fullword ascii
      $s18 = "GetFlagOn" fullword ascii
      $s19 = "flag_get_count" fullword ascii
      $s20 = "FloodFill2d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b {
   meta:
      description = "samples - file 5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b"
   strings:
      $s1 = "VBYBmp.exe" fullword wide
      $s2 = "LOGIN.XML" fullword wide
      $s3 = "QUANSD.Frm_LOGIN.resources" fullword ascii
      $s4 = "59524E436650" wide /* hex encoded string 'YRNCfP' */
      $s5 = "LOAD_LOGIN_SETTING" fullword ascii
      $s6 = "File_LOGIN_XML" fullword ascii
      $s7 = "Frm_Login_Load" fullword ascii
      $s8 = "btn_login_Click" fullword ascii
      $s9 = "I CSDL - SQL CONNECTION STRING" fullword wide
      $s10 = "VBYBmp.pdb" fullword ascii
      $s11 = "Frm_LOGIN" fullword wide
      $s12 = "txt_password" fullword wide
      $s13 = "btn_login" fullword wide
      $s14 = "CSDL.XML" fullword wide
      $s15 = "Check_Logged" fullword ascii
      $s16 = "GET_CURRENT_APP_PATH" fullword ascii
      $s17 = " - PHI" fullword wide
      $s18 = "the insert statement conflicted with the foreign key constraint" fullword wide
      $s19 = "the update statement conflicted with the foreign key constraint" fullword wide
      $s20 = " - KHO S" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f432a0fd {
   meta:
      description = "samples - file dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f432a0fd.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f432a0fd"
   strings:
      $s1 = "LOGIN.XML" fullword wide
      $s2 = "QUANSD.Frm_LOGIN.resources" fullword ascii
      $s3 = "VtlcaI.exe" fullword wide
      $s4 = "496847414573" wide /* hex encoded string 'IhGAEs' */
      $s5 = "LOAD_LOGIN_SETTING" fullword ascii
      $s6 = "File_LOGIN_XML" fullword ascii
      $s7 = "Frm_Login_Load" fullword ascii
      $s8 = "btn_login_Click" fullword ascii
      $s9 = "I CSDL - SQL CONNECTION STRING" fullword wide
      $s10 = "Frm_LOGIN" fullword wide
      $s11 = "txt_password" fullword wide
      $s12 = "btn_login" fullword wide
      $s13 = "CSDL.XML" fullword wide
      $s14 = "VtlcaI.pdb" fullword ascii
      $s15 = "Check_Logged" fullword ascii
      $s16 = "GET_CURRENT_APP_PATH" fullword ascii
      $s17 = " - PHI" fullword wide
      $s18 = "the insert statement conflicted with the foreign key constraint" fullword wide
      $s19 = "the update statement conflicted with the foreign key constraint" fullword wide
      $s20 = " - KHO S" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5 {
   meta:
      description = "samples - file bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5"
   strings:
      $s1 = "EasyAntiCheat.exe" fullword wide
      $s2 = "\"http://ocsp2.globalsign.com/rootr306" fullword ascii
      $s3 = "!http://ocsp.globalsign.com/rootr103" fullword ascii
      $s4 = "2http://ocsp2.globalsign.com/gsextendcodesignsha2g30U" fullword ascii
      $s5 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s6 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s7 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s8 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s9 = "%http://crl.globalsign.com/root-r3.crl0b" fullword ascii
      $s10 = "\"http://crl.globalsign.com/root.crl0G" fullword ascii
      $s11 = "http://ocsp.digicert.com0X" fullword ascii
      $s12 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii
      $s13 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii
      $s14 = "Bhttp://secure.globalsign.com/cacert/gsextendcodesignsha2g3ocsp.crt0>" fullword ascii
      $s15 = "4http://crl.globalsign.com/gsextendcodesignsha2g3.crl0" fullword ascii
      $s16 = "DigiCert Timestamp 2022 - 20" fullword ascii
      $s17 = ";GlobalSign Extended Validation CodeSigning CA - SHA256 - G3" fullword ascii
      $s18 = ";GlobalSign Extended Validation CodeSigning CA - SHA256 - G30" fullword ascii
      $s19 = " constructor or from DllMain." fullword ascii
      $s20 = "Z^W:\"a" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and
      8 of them
}

rule d440158b91d965693007b539131704b3bdd72e864b5adc1c0e230213acd3d97b {
   meta:
      description = "samples - file d440158b91d965693007b539131704b3bdd72e864b5adc1c0e230213acd3d97b.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d440158b91d965693007b539131704b3bdd72e864b5adc1c0e230213acd3d97b"
   strings:
      $s1 = "wowo.exe" fullword wide
      $s2 = "EncryptOrDecryptXOR" fullword ascii
      $s3 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" fullword wide /* base64 encoded string 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' */
      $s4 = "Select * from Win32_ComputerSystem" fullword wide
      $s5 = "enableFakeError" fullword ascii
      $s6 = ";F;<;2;" fullword ascii /* reversed goodware string ';2;<;F;' */
      $s7 = "doi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmh" wide
      $s8 = "mhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeud" wide
      $s9 = "zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeu" wide
      $s10 = "i0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeud" fullword wide
      $s11 = "yoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi" wide
      $s12 = "zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeu" wide
      $s13 = "oi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhy" wide
      $s14 = "hyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudoi0zmhyoeudo" wide
      $s15 = "vmware" fullword wide
      $s16 = "4B5.5/5{5" fullword ascii /* hex encoded string 'KUU' */
      $s17 = "EncryptInitalize" fullword ascii
      $s18 = "encryptType" fullword ascii
      $s19 = "3'4[4F4*454" fullword ascii /* hex encoded string '4ODT' */
      $s20 = "<EncryptOutput>b__2" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_09571623326972119f44c4f2e92b7dc4ef670a9238d21c4fbc671269da610ae5 {
   meta:
      description = "samples - file 09571623326972119f44c4f2e92b7dc4ef670a9238d21c4fbc671269da610ae5.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "09571623326972119f44c4f2e92b7dc4ef670a9238d21c4fbc671269da610ae5"
   strings:
      $s1 = "akh.exe" fullword wide
      $s2 = "EncryptOrDecryptXOR" fullword ascii
      $s3 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" fullword wide /* base64 encoded string 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' */
      $s4 = "Select * from Win32_ComputerSystem" fullword wide
      $s5 = "enableFakeError" fullword ascii
      $s6 = "vmware" fullword wide
      $s7 = "EncryptInitalize" fullword ascii
      $s8 = "encryptType" fullword ascii
      $s9 = "<EncryptOutput>b__2" fullword ascii
      $s10 = "EncryptOutput" fullword ascii
      $s11 = "<EncryptInitalize>b__0" fullword ascii
      $s12 = "i1zGh}omujoa0:mcygetdmi1znhyedudi.p|" fullword wide
      $s13 = ">'?;246*5}" fullword wide /* hex encoded string '$e' */
      $s14 = "hyoeudoi" fullword wide
      $s15 = "yoeudoi" fullword wide
      $s16 = "ivijojejuh" fullword ascii
      $s17 = "hjyjoje" fullword ascii
      $s18 = "miyoeqdoi" fullword wide
      $s19 = "yoeudoip" fullword wide
      $s20 = "hyoeudo" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule f5f16852761bc7fdf0327d60493d3910bf40f826d42b8bd84f145d5ed659ae6b {
   meta:
      description = "samples - file f5f16852761bc7fdf0327d60493d3910bf40f826d42b8bd84f145d5ed659ae6b.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "f5f16852761bc7fdf0327d60493d3910bf40f826d42b8bd84f145d5ed659ae6b"
   strings:
      $s1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD^V" fullword ascii
      $s2 = "BcRz.exe" fullword wide
      $s3 = "BcRz.pdb" fullword ascii
      $s4 = "logoPictureBox.Image" fullword wide
      $s5 = "get_AssemblyDescription" fullword ascii
      $s6 = "get_TK_TENDANGNHAP" fullword ascii
      $s7 = "getLichThi_HocPhan" fullword ascii
      $s8 = "getLichThi_ChungChi" fullword ascii
      $s9 = "getNamHoc_HocPhan" fullword ascii
      $s10 = "getLopChungChi" fullword ascii
      $s11 = "getThongTinTaiKhoan" fullword ascii
      $s12 = "getLopChuyenDe" fullword ascii
      $s13 = "getNamHoc_ChuyenDe" fullword ascii
      $s14 = "getLopHocPhan" fullword ascii
      $s15 = "getNam_ChungChi" fullword ascii
      $s16 = "get_DTO_MaLopCD" fullword ascii
      $s17 = "get_DTO_MaLoaiCC" fullword ascii
      $s18 = "getHocKy_ChuyenDe" fullword ascii
      $s19 = "get_DTO_MaLopCC" fullword ascii
      $s20 = "getHocKy_HocPhan" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214 {
   meta:
      description = "samples - file 82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214"
   strings:
      $x1 = "C:\\Users\\Administrator\\Desktop\\offline\\offlinee\\Light-The-Dark-1.0.1\\obj\\Debug\\Total Uninstall Professional.pdb" fullword ascii
      $s2 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
      $s3 = "TotalUninstall.exe" fullword wide
      $s4 = "Total Uninstall Professional.exe" fullword wide
      $s5 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii
      $s6 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s7 = "/data/sub.bat" fullword wide
      $s8 = "      <!-- Windows 8 -->" fullword ascii
      $s9 = "      <!-- Windows 8.1 -->" fullword ascii
      $s10 = "      <!-- Windows Vista -->" fullword ascii
      $s11 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii
      $s12 = "      <longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii
      $s13 = "      <!-- Windows 7 -->" fullword ascii
      $s14 = "      <!-- Windows 10 -->" fullword ascii
      $s15 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s16 = "             requestedExecutionLevel node with one of the following." fullword ascii
      $s17 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii
      $s18 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii
      $s19 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii
      $s20 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

rule e842b6dff73f8cc125170bafb505357263972cefc0d7187207295a207a6a3bdf {
   meta:
      description = "samples - file e842b6dff73f8cc125170bafb505357263972cefc0d7187207295a207a6a3bdf.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "e842b6dff73f8cc125170bafb505357263972cefc0d7187207295a207a6a3bdf"
   strings:
      $s1 = "SFkQtA.exe" fullword wide
      $s2 = "6F7A6A467372" wide /* hex encoded string 'ozjFsr' */
      $s3 = " --- COMPUTER ---" fullword wide
      $s4 = "SFkQtA.pdb" fullword ascii
      $s5 = " --- PLAYER ---" fullword wide
      $s6 = " ----- START NEW GAME -----" fullword wide
      $s7 = "GetSquares" fullword ascii
      $s8 = "GetViTri" fullword ascii
      $s9 = "getSquares" fullword ascii
      $s10 = "Player VS Computer" fullword wide
      $s11 = "eatting" fullword ascii
      $s12 = "setScoreComputer" fullword ascii
      $s13 = "L:\\8;-" fullword ascii
      $s14 = "srPH.bbP_t?mf" fullword ascii
      $s15 = "16.10.0.0" fullword ascii
      $s16 = "Minimax" fullword ascii
      $s17 = "get_ozjFsr" fullword ascii
      $s18 = "DoAnBaoCao.PVP.resources" fullword ascii
      $s19 = "DoAnBaoCao.PVC.resources" fullword ascii
      $s20 = " dich den " fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule sig_7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394 {
   meta:
      description = "samples - file 7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394"
   strings:
      $s1 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide
      $s2 = "C:\\A10\\0x18at80t1tofm\\output.pdb" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "http://www.image-line.com 0/" fullword ascii
      $s5 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s6 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s7 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s8 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s9 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s10 = "http://ocsp.digicert.com0X" fullword ascii
      $s11 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii
      $s12 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii
      $s13 = "/http://crl4.digicert.com/sha2-assured-cs-g1.crl0L" fullword ascii
      $s14 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s15 = "DigiCert Timestamp 2022 - 20" fullword ascii
      $s16 = "`template-parameter-" fullword ascii
      $s17 = ";&<7<@<E=|>" fullword ascii /* hex encoded string '~' */
      $s18 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii
      $s19 = "2 2%2;2@2E2[2`2e2{2" fullword ascii /* hex encoded string '""."."' */
      $s20 = "AppPolicyGetWindowingModel" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}

rule a7de3f00dfb9ba786eb5c6358692a605465aa2ca1b3c25e46c31f33a7fdaa6b4 {
   meta:
      description = "samples - file a7de3f00dfb9ba786eb5c6358692a605465aa2ca1b3c25e46c31f33a7fdaa6b4.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "a7de3f00dfb9ba786eb5c6358692a605465aa2ca1b3c25e46c31f33a7fdaa6b4"
   strings:
      $x1 = "c:\\windows\\system32\\ntdll.dll" fullword ascii
      $s2 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s3 = ".rdata$voltmd" fullword ascii
      $s4 = "Click-meow!" fullword ascii
      $s5 = "zIJE;-!" fullword ascii
      $s6 = "hgEb]Gp" fullword ascii
      $s7 = "TeOd5z*u|" fullword ascii
      $s8 = "SolGoodman" fullword ascii
      $s9 = "Baloe9ri" fullword ascii
      $s10 = "OG.qzj" fullword ascii
      $s11 = "FKhIS(q" fullword ascii
      $s12 = "AMD Software Adrenalin Edition" fullword wide
      $s13 = "AMD Inc." fullword wide /* Goodware String - occured 2 times */
      $s14 = "\\.3sv|" fullword ascii
      $s15 = "+KF'&Z4=E" fullword ascii
      $s16 = "[;ePqE" fullword ascii
      $s17 = " #- #" fullword ascii
      $s18 = ">y00 ,lC" fullword ascii
      $s19 = ">V}apm8" fullword ascii
      $s20 = "<c4q&gW" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule f91e4ff7811a5848561463d970c51870c9299a80117a89fb86a698b9f727de87 {
   meta:
      description = "samples - file f91e4ff7811a5848561463d970c51870c9299a80117a89fb86a698b9f727de87.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "f91e4ff7811a5848561463d970c51870c9299a80117a89fb86a698b9f727de87"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii
      $s2 = "WTRWLHJXZ" fullword ascii /* base64 encoded string 'Y4V,rW' */
      $s3 = "WTRWLHJBZW" fullword ascii /* base64 encoded string 'Y4V,rAe' */
      $s4 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s5 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s6 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s7 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s8 = "qfspmatrioafaosgigiwtrwlhjxzrifkqfrpmaqrioqfaovgig1wtrwlhjizrifkqftpmaurioqfaovgigiwtrwlhjyzrigkqfRpmaprioqfaovgigiwtrwlhjxzribk" ascii
      $s9 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii
      $s10 = "http://ocsp.digicert.com0X" fullword ascii
      $s11 = "OnpkMmpbs" fullword ascii /* base64 encoded string ':zd2j[' */
      $s12 = "->&%.>,7*,+%>5-F^P5;8165#0frp(\"1:,B4%%<7J*&$28>>-YX@W!!'YDPrp9-&-,,5.$03$-4((#;#$7)977%*\"09CBU>60*0\". ]CQigiw113$-G=96:'F2'?5" ascii
      $s13 = "http://ocsp.digicert.com0\\" fullword ascii
      $s14 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii
      $s15 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii
      $s16 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s17 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii
      $s18 = "zrifkqftpmaurioqfaovgigiwtrwlhjyzrigkqf" fullword ascii
      $s19 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii
      $s20 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 17000KB and
      8 of them
}

rule sig_327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba {
   meta:
      description = "samples - file 327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba"
   strings:
      $s1 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "C:\\A10\\x2x8cblh920\\output.pdb" fullword ascii
      $s4 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s5 = "`template-parameter-" fullword ascii
      $s6 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii
      $s7 = "AppPolicyGetWindowingModel" fullword ascii
      $s8 = "operator<=>" fullword ascii
      $s9 = "operator co_await" fullword ascii
      $s10 = "4&424>4]4" fullword ascii /* hex encoded string 'D$D' */
      $s11 = "6E\" 5d\"" fullword ascii /* hex encoded string 'n]' */
      $s12 = ";(<3<;=D=" fullword ascii /* hex encoded string '=' */
      $s13 = "3'424>4`4" fullword ascii /* hex encoded string '4$D' */
      $s14 = "<'=/=5=D=]=" fullword ascii /* hex encoded string ']' */
      $s15 = "nullptr" fullword ascii
      $s16 = "regex_error(error_stack): There was insufficient memory to determine whether the regular expression could match the specified ch" ascii
      $s17 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s18 = "Ewu.Luw7cQTXnFz=@Hu.Iuu7cQTTnFz=c@" fullword ascii
      $s19 = "inE0kLT.iFv" fullword ascii
      $s20 = "tJV.alc,AYa" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      8 of them
}

rule sig_6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599 {
   meta:
      description = "samples - file 6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599"
   strings:
      $s1 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "C:\\A10\\gixd3zu\\output.pdb" fullword ascii
      $s4 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s5 = "`template-parameter-" fullword ascii
      $s6 = "AppPolicyGetShowDeveloperDiagnostic" fullword ascii
      $s7 = "AppPolicyGetWindowingModel" fullword ascii
      $s8 = "operator<=>" fullword ascii
      $s9 = "operator co_await" fullword ascii
      $s10 = "@~{|@~{2A~{" fullword ascii /* hex encoded string '*' */
      $s11 = "BQ3irCki>Al" fullword ascii
      $s12 = ";%<4<\\<c<" fullword ascii /* hex encoded string 'L' */
      $s13 = "nullptr" fullword ascii
      $s14 = "regex_error(error_stack): There was insufficient memory to determine whether the regular expression could match the specified ch" ascii
      $s15 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s16 = "hEb.CIM<Ggx" fullword ascii
      $s17 = "9I9T:\\:h:u:|:" fullword ascii
      $s18 = "H:\\sIK^pN?'w;NZ" fullword ascii
      $s19 = " noexcept" fullword ascii
      $s20 = " volatile" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}

rule sig_5df688f5538aca79256dc329400ac5fb412000930d21072433733fa8417b9913 {
   meta:
      description = "samples - file 5df688f5538aca79256dc329400ac5fb412000930d21072433733fa8417b9913.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5df688f5538aca79256dc329400ac5fb412000930d21072433733fa8417b9913"
   strings:
      $s1 = " constructor or from DllMain." fullword ascii
      $s2 = "#?23~\\+'" fullword ascii /* hex encoded string '#' */
      $s3 = "NGPADDINGXXPADDINGPADD" fullword ascii
      $s4 = "1 -n,K" fullword ascii
      $s5 = "USpCfk69" fullword ascii
      $s6 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s7 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s8 = "T$h9T$" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "D$<RSP" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "L$PQSV" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide
      $s12 = " PnarK8U" fullword ascii
      $s13 = "f?aPLz\\4" fullword ascii
      $s14 = "+6[.zps;" fullword ascii
      $s15 = "d:LFRZ+N:" fullword ascii
      $s16 = "HuZSP#a" fullword ascii
      $s17 = "YjxKeC<s" fullword ascii
      $s18 = "bwfk!q" fullword ascii
      $s19 = "{TbVL%Km" fullword ascii
      $s20 = "ForceRemove" fullword ascii /* Goodware String - occured 1167 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and
      8 of them
}

rule ee80038271164361a38cc49e3b1c1ee446eda1c80181ffe161307d414c55fcdf {
   meta:
      description = "samples - file ee80038271164361a38cc49e3b1c1ee446eda1c80181ffe161307d414c55fcdf.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "ee80038271164361a38cc49e3b1c1ee446eda1c80181ffe161307d414c55fcdf"
   strings:
      $s1 = "effortdiscussion.exe" fullword ascii
      $s2 = "efforttdiscussion.exe" fullword ascii
      $s3 = "\"efforttdiscussion.exe\"" fullword ascii
      $s4 = "\"effortdiscussion.exe\"" fullword ascii
      $s5 = "3'4.474B4^4" fullword ascii /* hex encoded string '4GKD' */
      $s6 = "`[\\Ik:\\E" fullword ascii
      $s7 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s8 = "- 'X)/" fullword ascii
      $s9 = ")W<*C- " fullword ascii
      $s10 = "qz- b4:" fullword ascii
      $s11 = "zTehhyx" fullword ascii
      $s12 = "uvqYI!)" fullword ascii
      $s13 = "rEjk+i0X" fullword ascii
      $s14 = "jATM6tEr[C" fullword ascii
      $s15 = "kswc!1" fullword ascii
      $s16 = "Wwckov<" fullword ascii
      $s17 = "EyhU%>dc" fullword ascii
      $s18 = "EiBt\\lj" fullword ascii
      $s19 = "}EcLBzzWM6" fullword ascii
      $s20 = "jomB1KC" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e {
   meta:
      description = "samples - file 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
   strings:
      $s1 = "b6024062.exe" fullword ascii
      $s2 = "e6198054.exe" fullword ascii
      $s3 = "v9708420.exe" fullword ascii
      $s4 = "a8999626.exe" fullword ascii
      $s5 = "EREYEhE" fullword ascii
      $s6 = "GBGPGXG" fullword ascii
      $s7 = "Tc}CMd" fullword ascii
      $s8 = "\\QSjrzu[" fullword ascii
      $s9 = "azvhin" fullword ascii
      $s10 = "photo443" fullword ascii
      $s11 = "v\\* p!" fullword ascii
      $s12 = "OUAREff5" fullword ascii
      $s13 = "BJ)+ Q" fullword ascii
      $s14 = "TtJrwYf6" fullword ascii
      $s15 = "lTmpLr" fullword ascii
      $s16 = "whFWS'F" fullword ascii
      $s17 = "Dpkp28E8!" fullword ascii
      $s18 = "DIFI*o\\" fullword ascii
      $s19 = "Shks?U" fullword ascii
      $s20 = "OBbp\\Pd" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a {
   meta:
      description = "samples - file 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
   strings:
      $s1 = "y7657414.exe" fullword ascii
      $s2 = "m4625294.exe" fullword ascii
      $s3 = "9526.exe" fullword ascii
      $s4 = "n3607354.exe" fullword ascii
      $s5 = "NGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s6 = "[GLOgI" fullword ascii
      $s7 = "azvhin" fullword ascii
      $s8 = "v\\* p!" fullword ascii
      $s9 = "fotod250" fullword ascii
      $s10 = "ksew5\\" fullword ascii
      $s11 = "pXuoZ}J" fullword ascii
      $s12 = "+kemuPO%L=" fullword ascii
      $s13 = "[7EUUTTEEU" fullword ascii
      $s14 = "$KjqqBN!I$" fullword ascii
      $s15 = "QANL*8N" fullword ascii
      $s16 = "MwGM\\4]9L" fullword ascii
      $s17 = "urzfmZ3i8" fullword ascii
      $s18 = "RwZX(2#" fullword ascii
      $s19 = "Brnd`vO" fullword ascii
      $s20 = "UMkR4IV" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14 {
   meta:
      description = "samples - file 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
   strings:
      $s1 = "v5080964.exe" fullword ascii
      $s2 = "v6552833.exe" fullword ascii
      $s3 = "c1486811.exe" fullword ascii
      $s4 = "e2322851.exe" fullword ascii
      $s5 = "DEYE@Ac" fullword ascii
      $s6 = "t:\\AQ+" fullword ascii
      $s7 = "CK:\\B#|" fullword ascii
      $s8 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s9 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s10 = "\\)f- G" fullword ascii
      $s11 = "azvhin" fullword ascii
      $s12 = "photo443" fullword ascii
      $s13 = "v\\* p!" fullword ascii
      $s14 = "BJ)+ Q" fullword ascii
      $s15 = "Fj]0:NYs5+ " fullword ascii
      $s16 = "T v -P.P/P;" fullword ascii
      $s17 = "fipdid" fullword ascii
      $s18 = "iopYsz7" fullword ascii
      $s19 = "o_10 -l" fullword ascii
      $s20 = "E k?* " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc {
   meta:
      description = "samples - file 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
   strings:
      $s1 = "y7949226.exe" fullword ascii
      $s2 = "l2842523.exe" fullword ascii
      $s3 = "n2119150.exe" fullword ascii
      $s4 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s5 = "azvhin" fullword ascii
      $s6 = "v\\* p!" fullword ascii
      $s7 = "fotod250" fullword ascii
      $s8 = "zSSoR39" fullword ascii
      $s9 = "ksew5\\" fullword ascii
      $s10 = "pXuoZ}J" fullword ascii
      $s11 = "+kemuPO%L=" fullword ascii
      $s12 = "[7EUUTTEEU" fullword ascii
      $s13 = "$KjqqBN!I$" fullword ascii
      $s14 = "oWFcMuL" fullword ascii
      $s15 = "nxJCE/y" fullword ascii
      $s16 = "zDze\\i" fullword ascii
      $s17 = "^Y.GBs" fullword ascii
      $s18 = "tGZg>Om#" fullword ascii
      $s19 = ":aMpJkuxv" fullword ascii
      $s20 = "qPSXXa%" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f {
   meta:
      description = "samples - file 582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f"
   strings:
      $s1 = "n1834676.exe" fullword ascii
      $s2 = "y1133728.exe" fullword ascii
      $s3 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s4 = "Bsrioon" fullword ascii
      $s5 = "azvhin" fullword ascii
      $s6 = "v\\* p!" fullword ascii
      $s7 = "fotod250" fullword ascii
      $s8 = "BxWuAa2" fullword ascii
      $s9 = " -R{X}" fullword ascii
      $s10 = "dpllfh" fullword ascii
      $s11 = "ksew5\\" fullword ascii
      $s12 = "pXuoZ}J" fullword ascii
      $s13 = "+kemuPO%L=" fullword ascii
      $s14 = "[7EUUTTEEU" fullword ascii
      $s15 = "$KjqqBN!I$" fullword ascii
      $s16 = "vzoi\"]" fullword ascii
      $s17 = "oWFcMuL" fullword ascii
      $s18 = "zDze\\i" fullword ascii
      $s19 = "D6GNOg/qU" fullword ascii
      $s20 = "NVhoia~6^" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff {
   meta:
      description = "samples - file 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
   strings:
      $s1 = "e6298637.exe" fullword ascii
      $s2 = "v1902362.exe" fullword ascii
      $s3 = "c4455725.exe" fullword ascii
      $s4 = "v5119354.exe" fullword ascii
      $s5 = "EZ*GeTw!" fullword ascii
      $s6 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s7 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s8 = "azvhin" fullword ascii
      $s9 = "photo443" fullword ascii
      $s10 = "v\\* p!" fullword ascii
      $s11 = "+\"w* ]" fullword ascii
      $s12 = "%q* JF" fullword ascii
      $s13 = "ddxlbb" fullword ascii
      $s14 = "$ + 4Pp" fullword ascii
      $s15 = "BG[a- G;" fullword ascii
      $s16 = "ivouc21" fullword ascii
      $s17 = "MlgSEDg7" fullword ascii
      $s18 = "ksew5\\" fullword ascii
      $s19 = "#PWkQVII" fullword ascii
      $s20 = "UWIbQ*m" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0 {
   meta:
      description = "samples - file bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
   strings:
      $s1 = "b8097112.exe" fullword ascii
      $s2 = "e3029652.exe" fullword ascii
      $s3 = "v1023239.exe" fullword ascii
      $s4 = "rhsa -z" fullword ascii
      $s5 = "NGPADDINGXXPADDINGPADD" fullword ascii
      $s6 = "zH+Kyrat" fullword ascii
      $s7 = "azvhin" fullword ascii
      $s8 = "photo443" fullword ascii
      $s9 = "v\\* p!" fullword ascii
      $s10 = "zSSoR39" fullword ascii
      $s11 = "%e%N%P" fullword ascii
      $s12 = "IgIsci9" fullword ascii
      $s13 = "E6+ p7" fullword ascii
      $s14 = "/ -_Pb" fullword ascii
      $s15 = "^ /zk+" fullword ascii
      $s16 = "qxzprs" fullword ascii
      $s17 = ".CRm|g" fullword ascii
      $s18 = "ksew5\\" fullword ascii
      $s19 = "AvAB8e'" fullword ascii
      $s20 = "pXuoZ}J" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f {
   meta:
      description = "samples - file 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "y0282154.exe" fullword ascii
      $s2 = "n7372379.exe" fullword ascii
      $s3 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s4 = "|EYe\\j" fullword ascii
      $s5 = "azvhin" fullword ascii
      $s6 = "v\\* p!" fullword ascii
      $s7 = "fotod250" fullword ascii
      $s8 = "0- `@1v" fullword ascii
      $s9 = "ksew5\\" fullword ascii
      $s10 = "pXuoZ}J" fullword ascii
      $s11 = "+kemuPO%L=" fullword ascii
      $s12 = "[7EUUTTEEU" fullword ascii
      $s13 = "$KjqqBN!I$" fullword ascii
      $s14 = "OqwwTgT+" fullword ascii
      $s15 = "oWFcMuL" fullword ascii
      $s16 = "1eaaT5_sRB" fullword ascii
      $s17 = "^Y.GBs" fullword ascii
      $s18 = "mtPhm8m9" fullword ascii
      $s19 = "CSiEkoc" fullword ascii
      $s20 = "*J6JJJVJ\\JfJnJ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74 {
   meta:
      description = "samples - file b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74"
   strings:
      $s1 = "e2970528.exe" fullword ascii
      $s2 = "v3304238.exe" fullword ascii
      $s3 = "73^3242/_2b_`/" fullword ascii /* hex encoded string 's2B+' */
      $s4 = "pfpzpzn" fullword ascii
      $s5 = "#26%d%" fullword ascii
      $s6 = "6*?Y:\"" fullword ascii
      $s7 = "TUUUMUU" fullword ascii
      $s8 = "\\l%E%a" fullword ascii
      $s9 = "photo443" fullword ascii
      $s10 = "ojdkfa" fullword ascii
      $s11 = "\\ZWTI>uj*(zfM" fullword ascii
      $s12 = "{XxMn*k}" fullword ascii
      $s13 = "^esEex/M" fullword ascii
      $s14 = "RdKV1'," fullword ascii
      $s15 = "Q);aoaP!" fullword ascii
      $s16 = "PqbV^=c[_" fullword ascii
      $s17 = "ZuEE^{[" fullword ascii
      $s18 = "RwKg<eL" fullword ascii
      $s19 = "H``2feLD+lU" fullword ascii
      $s20 = "jyUq(se\"$" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f {
   meta:
      description = "samples - file dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
   strings:
      $s1 = "e8866881.exe" fullword ascii
      $s2 = "v8059576.exe" fullword ascii
      $s3 = "- -+-2-B-W-`-" fullword ascii
      $s4 = "n=Z:\\L" fullword ascii
      $s5 = "UWUUUUUUU" fullword ascii
      $s6 = " nKSPy" fullword ascii
      $s7 = "photo443" fullword ascii
      $s8 = "+ 65edo" fullword ascii
      $s9 = "#D /yr" fullword ascii
      $s10 = "urzfmZ3i8" fullword ascii
      $s11 = "RwZX(2#" fullword ascii
      $s12 = "uMas [$" fullword ascii
      $s13 = "ITjY|>K" fullword ascii
      $s14 = "YJWEDN+k" fullword ascii
      $s15 = "TanuM{FL" fullword ascii
      $s16 = "RSm#XYKS<K9" fullword ascii
      $s17 = "VGt4<GVSjF=A" fullword ascii
      $s18 = "ZDKd4dR" fullword ascii
      $s19 = "T!WvdMjI^=" fullword ascii
      $s20 = "#RYmQXKK" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af {
   meta:
      description = "samples - file fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af"
   strings:
      $s1 = "x0241203.exe" fullword ascii
      $s2 = "i1652240.exe" fullword ascii
      $s3 = "j3594998.exe" fullword ascii
      $s4 = "x0917721.exe" fullword ascii
      $s5 = "MzvMw.fpk" fullword ascii
      $s6 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s7 = "NGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
      $s8 = "Cqynejq" fullword ascii
      $s9 = "2@^- z" fullword ascii
      $s10 = "| /x{4" fullword ascii
      $s11 = "%0(SO -m" fullword ascii
      $s12 = "foto5566" fullword ascii
      $s13 = "QtIgr2G10" fullword ascii
      $s14 = "RSIdm7z" fullword ascii
      $s15 = "igjgwG|g" fullword ascii
      $s16 = "tYCqH!" fullword ascii
      $s17 = "<Q\\vWcV|s2w!u" fullword ascii
      $s18 = "DXZq4-X" fullword ascii
      $s19 = "JAst>mX" fullword ascii
      $s20 = "tPubuzu" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400 {
   meta:
      description = "samples - file f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400"
   strings:
      $s1 = "t6378141.exe" fullword ascii
      $s2 = "z3365500.exe" fullword ascii
      $s3 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s4 = "ffzndd" fullword ascii
      $s5 = "OrUo+ " fullword ascii
      $s6 = "XoYMgQ6" fullword ascii
      $s7 = "OqwwTgT+" fullword ascii
      $s8 = "ySNfX%5K" fullword ascii
      $s9 = "}MhqH?" fullword ascii
      $s10 = "1XtVIRI8" fullword ascii
      $s11 = "wExJ~Np" fullword ascii
      $s12 = "FRzYx% " fullword ascii
      $s13 = "Okink,?" fullword ascii
      $s14 = "bXAIY\\&U" fullword ascii
      $s15 = "ODZDzF/" fullword ascii
      $s16 = "KVCy6b7" fullword ascii
      $s17 = "'DToqaJt" fullword ascii
      $s18 = "6IoRIqjd" fullword ascii
      $s19 = ")DfEJl--" fullword ascii
      $s20 = "jlqZ(pS" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1 {
   meta:
      description = "samples - file 7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1"
   strings:
      $s1 = "t0809726.exe" fullword ascii
      $s2 = "z5326542.exe" fullword ascii
      $s3 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s4 = "OrUo+ " fullword ascii
      $s5 = "XoYMgQ6" fullword ascii
      $s6 = "\\nZLPW3|" fullword ascii
      $s7 = "mf2q- " fullword ascii
      $s8 = "}MhqH?" fullword ascii
      $s9 = "ODZDzF/" fullword ascii
      $s10 = "t)vIxI.b2" fullword ascii
      $s11 = "PM@MdMdMdMdMdMdGdZ1" fullword ascii
      $s12 = "TGRx=QE" fullword ascii
      $s13 = "uETE~@l" fullword ascii
      $s14 = "ZkOh%Ih" fullword ascii
      $s15 = "mtPhm8m9" fullword ascii
      $s16 = "XgBr0aa" fullword ascii
      $s17 = "vixo\\z" fullword ascii
      $s18 = "3CPpZ#\\a" fullword ascii
      $s19 = "TvqT\\mR" fullword ascii
      $s20 = "Q]QlQpREROBQ`|" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1 {
   meta:
      description = "samples - file df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1"
   strings:
      $s1 = "c4892591.exe" fullword ascii
      $s2 = "e4847811.exe" fullword ascii
      $s3 = "v9109127.exe" fullword ascii
      $s4 = "v0322221.exe" fullword ascii
      $s5 = "'7,/@(b\\" fullword ascii /* hex encoded string '{' */
      $s6 = "S:\"7*QC" fullword ascii
      $s7 = "wot.AGH" fullword ascii
      $s8 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s9 = "NGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s10 = "9!ftpG1" fullword ascii
      $s11 = "photo443" fullword ascii
      $s12 = "gtdnzm" fullword ascii
      $s13 = "\\ShTo>\\" fullword ascii
      $s14 = "\\)SRSBUZ+yJ" fullword ascii
      $s15 = "%fz%2Z" fullword ascii
      $s16 = "+ ['Y;" fullword ascii
      $s17 = ";*= /zv" fullword ascii
      $s18 = "fzCmrsl" fullword ascii
      $s19 = "zYpL34dpf" fullword ascii
      $s20 = "yqcPf!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5 {
   meta:
      description = "samples - file 5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5"
   strings:
      $s1 = "j5687512.exe" fullword ascii
      $s2 = "x9832368.exe" fullword ascii
      $s3 = "h7532393.exe" fullword ascii
      $s4 = "XsCl]+ " fullword ascii
      $s5 = "NGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s6 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii
      $s7 = "eYE;F`^8" fullword ascii
      $s8 = "foto5566" fullword ascii
      $s9 = "PiTadpJ2" fullword ascii
      $s10 = "-UO+ UF" fullword ascii
      $s11 = "ffxndd" fullword ascii
      $s12 = "urzfmZ3i8" fullword ascii
      $s13 = ">TPdmktH" fullword ascii
      $s14 = "A5.yjn" fullword ascii
      $s15 = "uUwUTE3Trfu" fullword ascii
      $s16 = "yrQRt^iq" fullword ascii
      $s17 = "RMBB{@f" fullword ascii
      $s18 = "DBNUH\"%" fullword ascii
      $s19 = "woswBo/co" fullword ascii
      $s20 = "IHpHmlE" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48 {
   meta:
      description = "samples - file f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48"
   strings:
      $s1 = "i0682271.exe" fullword ascii
      $s2 = "x9880725.exe" fullword ascii
      $s3 = "j0548428.exe" fullword ascii
      $s4 = "x0853562.exe" fullword ascii
      $s5 = "3333333353" ascii /* hex encoded string '3333S' */
      $s6 = "NGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s7 = "eYE;F`^8" fullword ascii
      $s8 = "foto5566" fullword ascii
      $s9 = "hLI(F -6" fullword ascii
      $s10 = "w. /oh" fullword ascii
      $s11 = "RxANR_3" fullword ascii
      $s12 = "urzfmZ3i8" fullword ascii
      $s13 = "xgQV+-c" fullword ascii
      $s14 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* Goodware String - occured 1 times */
      $s15 = "#RVpx!" fullword ascii
      $s16 = "tYMp({1" fullword ascii
      $s17 = "awTbN4MF" fullword ascii
      $s18 = "Oyyvmr}" fullword ascii
      $s19 = "YORI++y`" fullword ascii
      $s20 = "Lyao]4N{" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule d6a1a23efa1aa9e632f9e111e21070f0390678592d94fc75370d4325f45cf5d7 {
   meta:
      description = "samples - file d6a1a23efa1aa9e632f9e111e21070f0390678592d94fc75370d4325f45cf5d7.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d6a1a23efa1aa9e632f9e111e21070f0390678592d94fc75370d4325f45cf5d7"
   strings:
      $s1 = "C:\\Windows\\System32\\Werfault.exe" fullword wide
      $s2 = "C:\\Windows\\SysWOW64\\Werfault.exe" fullword wide
      $s3 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s4 = "/test.txt" fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s6 = "X-Havoc-Agent: Demon" fullword wide
      $s7 = "/helloworld.js" fullword wide
      $s8 = "/index.php" fullword wide
      $s9 = "AVAUATI" fullword ascii
      $s10 = "AVAUATA" fullword ascii
      $s11 = "AWAVAUATL" fullword ascii
      $s12 = "AVAUATWVSL" fullword ascii
      $s13 = "AWAVAUI" fullword ascii
      $s14 = "AWAVAUATI" fullword ascii
      $s15 = "157.245.47.66" fullword wide
      $s16 = "AWAVAUATU1" fullword ascii
      $s17 = "AWAVAUE1" fullword ascii
      $s18 = "AVAUATE1" fullword ascii
      $s19 = "l$hA9}" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "_A\\A]A^" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule ebdc54df582be1cafb91a1948657212fe50229b09071b1cbb3d1b660cc707fc5 {
   meta:
      description = "samples - file ebdc54df582be1cafb91a1948657212fe50229b09071b1cbb3d1b660cc707fc5.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "ebdc54df582be1cafb91a1948657212fe50229b09071b1cbb3d1b660cc707fc5"
   strings:
      $s1 = "C:\\Windows\\System32\\Werfault.exe" fullword wide
      $s2 = "C:\\Windows\\SysWOW64\\Werfault.exe" fullword wide
      $s3 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s4 = "/test.txt" fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s6 = "X-Havoc-Agent: Demon" fullword wide
      $s7 = "/helloworld.js" fullword wide
      $s8 = "/index.php" fullword wide
      $s9 = "AVAUATI" fullword ascii
      $s10 = "AVAUATA" fullword ascii
      $s11 = "AWAVAUATL" fullword ascii
      $s12 = "AVAUATWVSL" fullword ascii
      $s13 = "AWAVAUI" fullword ascii
      $s14 = "AWAVAUATI" fullword ascii
      $s15 = "AWAVAUATUWVH" fullword ascii
      $s16 = "157.245.47.66" fullword wide
      $s17 = "AWAVAUATU1" fullword ascii
      $s18 = "AWAVAUE1" fullword ascii
      $s19 = "AVAUATE1" fullword ascii
      $s20 = "l$hA9}" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_37a6ef95815119e73613aa856f88a70ace7ce8dffa6e0b131b6f148f2dd37fc8 {
   meta:
      description = "samples - file 37a6ef95815119e73613aa856f88a70ace7ce8dffa6e0b131b6f148f2dd37fc8.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "37a6ef95815119e73613aa856f88a70ace7ce8dffa6e0b131b6f148f2dd37fc8"
   strings:
      $s1 = "C:\\Windows\\System32\\Werfault.exe" fullword wide
      $s2 = "C:\\Windows\\SysWOW64\\Werfault.exe" fullword wide
      $s3 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s4 = "/test.txt" fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s6 = "X-Havoc-Agent: Demon" fullword wide
      $s7 = "/helloworld.js" fullword wide
      $s8 = "/index.php" fullword wide
      $s9 = "AVAUATI" fullword ascii
      $s10 = "AVAUATA" fullword ascii
      $s11 = "AWAVAUATL" fullword ascii
      $s12 = "AVAUATWVSL" fullword ascii
      $s13 = "AWAVAUI" fullword ascii
      $s14 = "AWAVAUATI" fullword ascii
      $s15 = "AWAVAUATUWVH" fullword ascii
      $s16 = "157.245.47.66" fullword wide
      $s17 = "AWAVAUATU1" fullword ascii
      $s18 = "AWAVAUE1" fullword ascii
      $s19 = "AVAUATE1" fullword ascii
      $s20 = "l$hA9}" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule d4163f1179d58f842ba3b9cd28cd315de031669b93d87111c40fbc13167e42ab {
   meta:
      description = "samples - file d4163f1179d58f842ba3b9cd28cd315de031669b93d87111c40fbc13167e42ab.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d4163f1179d58f842ba3b9cd28cd315de031669b93d87111c40fbc13167e42ab"
   strings:
      $s1 = "C:\\Windows\\System32\\Werfault.exe" fullword wide
      $s2 = "C:\\Windows\\SysWOW64\\Werfault.exe" fullword wide
      $s3 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s4 = "/test.txt" fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s6 = "X-Havoc-Agent: Demon" fullword wide
      $s7 = "/helloworld.js" fullword wide
      $s8 = "/index.php" fullword wide
      $s9 = "AVAUATI" fullword ascii
      $s10 = "AVAUATA" fullword ascii
      $s11 = "AWAVAUATL" fullword ascii
      $s12 = "AVAUATWVSL" fullword ascii
      $s13 = "AWAVAUI" fullword ascii
      $s14 = "AWAVAUATI" fullword ascii
      $s15 = "157.245.47.66" fullword wide
      $s16 = "AWAVAUATU1" fullword ascii
      $s17 = "AWAVAUE1" fullword ascii
      $s18 = "AVAUATE1" fullword ascii
      $s19 = "l$hA9}" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "_A\\A]A^" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a_1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965a_0 {
   meta:
      description = "samples - from files a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a.exe, 1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a"
      hash2 = "1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3"
   strings:
      $s1 = "get_MainDomains" fullword ascii
      $s2 = "010B0F610C3D2E631E28190D0228672C100765690D140B310138202D1F1B0F610C3A0F661B02011C032B102717063A281F17251637381A2B0219751A00077415" ascii
      $s3 = "10250E1103111C350C14160737113908073B1E12121318221232370C110C1414103F03310F04121711143508073B1E121C1318041232640A162A1414103F0339" ascii
      $s4 = "02021411000139007C323134130C041436681C130C043C271F2C217A202B361104131C371D2C23711E0C31782F1104130F06202C1B3F1F3F0B10266504617D1D" ascii
      $s5 = "104130C041A142304103D0202103104130C04121D3F0419351D7813371C130C0727232522130C06341422062479131132110415342A171E7B2216066A1E141A2" ascii
      $s6 = "0932092A242A041217392D160C1412123400310C0412103F121308041132126E790C041217110F241A221214122B657D041214150E1726071214092A060C0012" ascii
      $s7 = "111D643C131C0416333A04100C040227023C26000E621022133B3927121D6702130C04161E612A357B721D38122C3B66041214170E1075071214090434271411" ascii
      $s8 = "3D3A111C1639041066320221132C1F0F3C240424063B00073E220275112408113A27111D0E2E12177B32033906383E120625180816021107793A1427163D0410" ascii
      $s9 = "6A3A176311070017343202211328170873240403066008006B22031D161400162C2714260E2A16106632031E066710157D251E32173415002B3A142716210017" ascii
      $s10 = "07286129172967160B1F7A3C321E171418172A213411341E7D3C32271327397F07110761762B063F31141C022426152B003C1D381F736639137C3C0A2005061D" ascii
      $s11 = "15041B7E352614130B102F22123F0128660C0C631B250411032C3132112F0B7F71121C601F270C061D1D32221327161461110C62213012161E0E302A04390662" ascii
      $s12 = "3E66363B1E69083B3C7234193D1C0A06201F3E14012A7B7C003C7F71067F020A167B6A117E740B3E19280B020412141104172103073E03300320061016600413" ascii
      $s13 = "3432101804146D1127250F3612131D04360C072A14172E132E04111B1102070C273417610417260437141229130A7512193707180C0263140914102304140011" ascii
      $s14 = "040214126A25080412336807130C0D1E1401041120141A14111F390F0824120A04030C073E04150413172E11141102080C1412172A04170C04093E1404130A1F" ascii
      $s15 = "0C04121411001F072E3B1C01070104043B113304130E041204272805082D0613192211140B24141104130F01100F3F16170C1039141B22610C04123211001F07" ascii
      $s16 = "1C2D372E631C363B33231524262F391D2114100F081E3836701A200D1C6D353F2A02216460162D143537142C353C6428262037397D01791F1E3F2203070F0167" ascii
      $s17 = "0A16236A7C7A68001D09727C7A7F7D3D3B221214122F35666A7C7A7F0E1A2607121409711D2B6A7C7A292D6A0C1412121F013C626A7C6D1104130C111E140504" ascii
      $s18 = "3E041504132B7D11141102080C120A161104151704040C1208250804120F3B071F3A033E1401041020141538111F390F0412120A040514072914150413172E11" ascii
      $s19 = "1574012332772A18240B17051F0A2575121D6401132A077817110C132B220616110D1C2121156C1A273F217532021636000A292A0F070B622F761960110D660A" ascii
      $s20 = "2D016E340C3F38166204793A046410137225667212623B063B0C6A1A146800110B2D17011172390E0C2B113C046A26060307143D137400100C28016A0C7C3816" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26_f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452ac_1 {
   meta:
      description = "samples - from files b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26.exe, f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26"
      hash2 = "f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f"
   strings:
      $x1 = "jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
      $x2 = "jSystem.CodeDom.MemberAttributes, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089fSystem.Drawing.Size," ascii
      $s3 = " System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3amSystem.Globalization.CultureInfo, mscorlib, V" ascii
      $s4 = "ersion=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089PADPADP" fullword ascii
      $s5 = "* labelErrorApellido" fullword wide
      $s6 = "* labelErrorNombre" fullword wide
      $s7 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii
      $s8 = "get_labelErrorApellifo" fullword ascii
      $s9 = "get_VariableServices" fullword ascii
      $s10 = "get_cmdControls" fullword ascii
      $s11 = "get_cmdExit" fullword ascii
      $s12 = "get_labelErrorNombre" fullword ascii
      $s13 = "'System.Globalization.DateTimeFormatInfo+" fullword ascii
      $s14 = "(System.Globalization.DateTimeFormatFlags" fullword ascii
      $s15 = "System.Globalization.TextInfo%System.Globalization.NumberFormatInfo'System.Globalization.DateTimeFormatInfo&System.Globalization" ascii
      $s16 = "QuanLyBanGiay.CCM" fullword wide
      $s17 = "cmd1Player.DefaultModifiers" fullword wide
      $s18 = "cmd1Player.Locked" fullword wide
      $s19 = "cmd1Player.Modifiers" fullword wide
      $s20 = "cmd2Player.DefaultModifiers" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41_59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72e_2 {
   meta:
      description = "samples - from files 004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41.exe, 59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41"
      hash2 = "59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0"
   strings:
      $s1 = "PostProcessor" fullword ascii
      $s2 = "InvokeProcessor" fullword ascii
      $s3 = "LoginDescriptor" fullword ascii
      $s4 = "CompareProcessor" fullword ascii
      $s5 = "LoginListener" fullword ascii
      $s6 = "ComputeProcessor" fullword ascii
      $s7 = "LoginProcessor" fullword ascii
      $s8 = "LogoutTemplate" fullword ascii
      $s9 = "ChangeTemplate" fullword ascii
      $s10 = "SetupProcessor" fullword ascii
      $s11 = "RateProcessor" fullword ascii
      $s12 = "AwakeProcessor" fullword ascii
      $s13 = "LoginMap" fullword ascii
      $s14 = "ManageProcessor" fullword ascii
      $s15 = "NewProcessor" fullword ascii
      $s16 = "PopProcessor" fullword ascii
      $s17 = "ExcludeProcessor" fullword ascii
      $s18 = "LogoutProcessor" fullword ascii
      $s19 = "LogoutDescriptor" fullword ascii
      $s20 = "LoginVisitor" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b_dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f4_3 {
   meta:
      description = "samples - from files 5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b.exe, dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f432a0fd.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b"
      hash2 = "dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f432a0fd"
   strings:
      $s1 = "LOGIN.XML" fullword wide
      $s2 = "QUANSD.Frm_LOGIN.resources" fullword ascii
      $s3 = "LOAD_LOGIN_SETTING" fullword ascii
      $s4 = "File_LOGIN_XML" fullword ascii
      $s5 = "Frm_Login_Load" fullword ascii
      $s6 = "btn_login_Click" fullword ascii
      $s7 = "I CSDL - SQL CONNECTION STRING" fullword wide
      $s8 = "Frm_LOGIN" fullword wide
      $s9 = "txt_password" fullword wide
      $s10 = "btn_login" fullword wide
      $s11 = "CSDL.XML" fullword wide
      $s12 = "Check_Logged" fullword ascii
      $s13 = "GET_CURRENT_APP_PATH" fullword ascii
      $s14 = " - PHI" fullword wide
      $s15 = "the insert statement conflicted with the foreign key constraint" fullword wide
      $s16 = "the update statement conflicted with the foreign key constraint" fullword wide
      $s17 = " - KHO S" fullword wide
      $s18 = "M - CHI TI" fullword wide
      $s19 = "N - CHI TI" fullword wide
      $s20 = "C - NH" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36_004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00d_4 {
   meta:
      description = "samples - from files 8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36.exe, 004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41.exe, 59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36"
      hash2 = "004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41"
      hash3 = "59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0"
   strings:
      $s1 = "ManageTemplate" fullword ascii
      $s2 = "PostTemplate" fullword ascii
      $s3 = "LoginField" fullword ascii
      $s4 = "LoginObject" fullword ascii
      $s5 = "LoginItem" fullword ascii
      $s6 = "LoginCode" fullword ascii
      $s7 = "LoginMethod" fullword ascii
      $s8 = "LoginWrapper" fullword ascii
      $s9 = "LoginAttribute" fullword ascii
      $s10 = "ReadTemplate" fullword ascii
      $s11 = "PostToken" fullword ascii
      $s12 = "ResolveTemplate" fullword ascii
      $s13 = "ComputeTemplate" fullword ascii
      $s14 = "PatchTemplate" fullword ascii
      $s15 = "NewTemplate" fullword ascii
      $s16 = "QueryTemplate" fullword ascii
      $s17 = "RateTemplate" fullword ascii
      $s18 = "CountTemplate" fullword ascii
      $s19 = "FillTemplate" fullword ascii
      $s20 = "DestroyTemplate" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2_8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc9_5 {
   meta:
      description = "samples - from files 2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2.exe, 8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2"
      hash2 = "8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f"
   strings:
      $s1 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii
      $s2 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide
      $s3 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide
      $s4 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide
      $s5 = "minkernel\\crts\\ucrt\\src\\appcrt\\internal\\win_policies.cpp" fullword wide
      $s6 = "minkernel\\crts\\ucrt\\src\\appcrt\\lowio\\close.cpp" fullword wide
      $s7 = "minkernel\\crts\\ucrt\\src\\appcrt\\convert\\c32rtomb.cpp" fullword wide
      $s8 = "c32 < (1u << (7 - trail_bytes))" fullword wide
      $s9 = "locale->locinfo->_public._locale_lc_codepage != CP_UTF8 && L\"UTF-8 isn't supported in this _mbtowc_l function yet!!!\"" fullword wide
      $s10 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_win32_buffer.h" fullword ascii
      $s11 = "mb_buf_used + bytes_to_add < mb_buf_size" fullword wide
      $s12 = "strcpy_s( p, result_buffer_count == (static_cast<size_t>(-1)) ? result_buffer_count : result_buffer_count - (p - result_buffer)," wide
      $s13 = " Data: <%s> %s" fullword ascii
      $s14 = "1 < mb_len && mb_buf_used < mb_len" fullword wide
      $s15 = "VCCRT\\vcruntime\\inc\\internal_shared.h" fullword wide
      $s16 = "retval != __crt_mbstring::INCOMPLETE" fullword wide
      $s17 = "1 <= trail_bytes && trail_bytes <= 3" fullword wide
      $s18 = "locale->locinfo->_public._locale_mb_cur_max == 1 || locale->locinfo->_public._locale_mb_cur_max == 2" fullword wide
      $s19 = "locale->locinfo->_public._locale_mb_cur_max > 1" fullword wide
      $s20 = "Client hook allocation failure." fullword ascii /* Goodware String - occured 14 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _645168fedeed9948b5103f10d52c9adf1133358e1b1ab4ac0893dd3bb73b2df5_adeeb5ab4974433126bf0c2d15234dc13fcd577217babbf0d352517ec5_6 {
   meta:
      description = "samples - from files 645168fedeed9948b5103f10d52c9adf1133358e1b1ab4ac0893dd3bb73b2df5.exe, adeeb5ab4974433126bf0c2d15234dc13fcd577217babbf0d352517ec588b7af.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "645168fedeed9948b5103f10d52c9adf1133358e1b1ab4ac0893dd3bb73b2df5"
      hash2 = "adeeb5ab4974433126bf0c2d15234dc13fcd577217babbf0d352517ec588b7af"
   strings:
      $s1 = "  <description>Isolation Notify</description>" fullword ascii
      $s2 = "aaadddeeee" ascii
      $s3 = "A$00$0A@VCComTypeInfoHolder@ATL@@@ATL@@" fullword ascii
      $s4 = "      version=\"1.0.0.0\"" fullword ascii
      $s5 = "CDDCCCCCCC" ascii
      $s6 = "DDDDEDEEEEEB" ascii
      $s7 = "DDDCDCDECEC" ascii
      $s8 = "DDDDDDCCECCB" ascii
      $s9 = "      name=\"napstat.exe\"" fullword ascii
      $s10 = "D9d$$t " fullword ascii /* Goodware String - occured 1 times */
      $s11 = "T$`D+|$T" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "H;KXs_H" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "?KKGI<8;" fullword ascii
      $s14 = ";{Du99kDu" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "fD;'sCI" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "i(f;k(u7I" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "t%fE;0sH" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "D$ u^D" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "H9KHt'H" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "H!{8H!{" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36_59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72e_7 {
   meta:
      description = "samples - from files 8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36.exe, 59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36"
      hash2 = "59a5e46b3173bc33c36e91ea80c13771e4f760011e59d360f84070b72ebb28d0"
   strings:
      $s1 = "LoginConfiguration" fullword ascii
      $s2 = "LoginParams" fullword ascii
      $s3 = "LoginParameter" fullword ascii
      $s4 = "LoginBridge" fullword ascii
      $s5 = "PostConfiguration" fullword ascii
      $s6 = "configsize" fullword ascii
      $s7 = "isconnection" fullword ascii
      $s8 = "PrintTemplate" fullword ascii
      $s9 = "startconfig" fullword ascii
      $s10 = "DefineTemplate" fullword ascii
      $s11 = "DeleteTemplate" fullword ascii
      $s12 = "RunConfiguration" fullword ascii
      $s13 = "LogoutBridge" fullword ascii
      $s14 = "PostInitializer" fullword ascii
      $s15 = "PostBridge" fullword ascii
      $s16 = "GetBridge" fullword ascii
      $s17 = "LogoutParameter" fullword ascii
      $s18 = "PostParameter" fullword ascii
      $s19 = "LogoutParams" fullword ascii
      $s20 = "insert_VISITORAt" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36_004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00d_8 {
   meta:
      description = "samples - from files 8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36.exe, 004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36"
      hash2 = "004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41"
   strings:
      $s1 = "LoginService" fullword ascii
      $s2 = "LoginThread" fullword ascii
      $s3 = "LoginModel" fullword ascii
      $s4 = "LoginCreator" fullword ascii
      $s5 = "m_Process" fullword ascii
      $s6 = "LoginRule" fullword ascii
      $s7 = "LoginReg" fullword ascii
      $s8 = "LoginException" fullword ascii
      $s9 = "LoginQueue" fullword ascii
      $s10 = "RunTemplate" fullword ascii
      $s11 = "LogoutService" fullword ascii
      $s12 = "ChangeThread" fullword ascii
      $s13 = "PostThread" fullword ascii
      $s14 = "LogoutThread" fullword ascii
      $s15 = "ManageThread" fullword ascii
      $s16 = "InvokeThread" fullword ascii
      $s17 = "TestTemplate" fullword ascii
      $s18 = "ExcludeTemplate" fullword ascii
      $s19 = "lengthtoken" fullword ascii
      $s20 = "versionident" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36_8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4_9 {
   meta:
      description = "samples - from files 8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36.exe, 8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36"
      hash2 = "8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943"
   strings:
      $s1 = "System.Collections.Generic.IEnumerator<System.Boolean>.get_Current" fullword ascii
      $s2 = "Failed to read LZW header" fullword wide
      $s3 = "Descriptor compressed size mismatch" fullword wide
      $s4 = "The Password property must be set before AES encrypted entries can be added" fullword wide
      $s5 = "Exception during test - '" fullword wide
      $s6 = "Creation of AES encrypted entries is not supported" fullword wide
      $s7 = "Header properties were accessed before header had been successfully read" fullword wide
      $s8 = "Unsupported bits set in the header." fullword wide
      $s9 = "Input stream could not be decoded" fullword wide
      $s10 = "System.Collections.Generic.IEnumerator<System.Boolean>.Current" fullword ascii
      $s11 = "Descriptor CRC mismatch" fullword wide
      $s12 = "Descriptor size mismatch" fullword wide
      $s13 = "Inflater dynamic header end-of-block code missing" fullword wide
      $s14 = "Wrong LZW header. Magic bytes don't match. 0x{0:x2} 0x{1:x2}" fullword wide
      $s15 = "Wrong local header signature at 0x{0:x}, expected 0x{1:x8}, actual 0x{2:x8}" fullword wide
      $s16 = "Input stream is in a unsupported format" fullword wide
      $s17 = "InflaterInputStream Length is not supported" fullword wide
      $s18 = "Stream compressed with " fullword wide
      $s19 = "Compression level must be 0-9" fullword wide
      $s20 = "8DECDB10AEFDB828B1325DD76119F2587EA785882269C22B7818DF39260394A9" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a521_10 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74.exe, fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af.exe, 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe, 5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5.exe, f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400.exe, 582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f.exe, 7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1.exe, dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe, ee80038271164361a38cc49e3b1c1ee446eda1c80181ffe161307d414c55fcdf.exe, f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe, df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74"
      hash3 = "fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af"
      hash4 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash5 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash6 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
      hash7 = "5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5"
      hash8 = "f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400"
      hash9 = "582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f"
      hash10 = "7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1"
      hash11 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
      hash12 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
      hash13 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
      hash14 = "ee80038271164361a38cc49e3b1c1ee446eda1c80181ffe161307d414c55fcdf"
      hash15 = "f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48"
      hash16 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
      hash17 = "df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1"
   strings:
      $s1 = "DSystem\\CurrentControlSet\\Control\\Session Manager" fullword ascii
      $s2 = "  <description>IExpress extraction tool</description>" fullword ascii
      $s3 = "          processorArchitecture=\"x86\"" fullword ascii
      $s4 = "     processorArchitecture=\"x86\"" fullword ascii
      $s5 = "  <assemblyIdentity version=\"5.1.0.0\"" fullword ascii
      $s6 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-->            " fullword ascii
      $s7 = "    <!-- This Id value indicates the application supports Windows Threshold functionality-->            " fullword ascii
      $s8 = "            <!--This Id value indicates the application supports Windows Vista/Server 2008 functionality -->" fullword ascii
      $s9 = "RUNPROGRAM" fullword wide /* Goodware String - occured 9 times */
      $s10 = "Extracting" fullword wide /* Goodware String - occured 13 times */
      $s11 = "CABINET" fullword wide /* Goodware String - occured 39 times */
      $s12 = "REBOOT" fullword wide /* Goodware String - occured 49 times */
      $s13 = "PendingFileRenameOperations" fullword ascii /* Goodware String - occured 52 times */
      $s14 = "RegServer" fullword ascii /* Goodware String - occured 57 times */
      $s15 = "Reboot" fullword ascii /* Goodware String - occured 105 times */
      $s16 = "Internet Explorer" fullword wide /* Goodware String - occured 518 times */
      $s17 = ".rdata$brc" fullword ascii
      $s18 = "WWj WWWSW" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "WEXTRACT.EXE            .MUI" fullword wide /* Goodware String - occured 1 times */
      $s20 = "D$HjDj" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252_35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f9_11 {
   meta:
      description = "samples - from files 9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252.exe, 35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7.exe, 1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715.exe, d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252"
      hash2 = "35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7"
      hash3 = "1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715"
      hash4 = "d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366"
   strings:
      $x1 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */
      $x2 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */
      $x3 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */
      $x4 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */
      $x5 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */
      $s6 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */
      $s7 = "SSPICLI.DLL" fullword wide
      $s8 = "UXTheme.dll" fullword wide
      $s9 = "oleaccrc.dll" fullword wide
      $s10 = "dnsapi.DLL" fullword wide
      $s11 = "iphlpapi.DLL" fullword wide
      $s12 = "WINNSI.DLL" fullword wide
      $s13 = "sfxrar.exe" fullword ascii
      $s14 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" fullword ascii
      $s15 = "  processorArchitecture=\"*\"" fullword ascii
      $s16 = "<pi-ms-win-core-processthreads-l1-1-2" fullword wide
      $s17 = "  version=\"1.0.0.0\"" fullword ascii
      $s18 = "s:IDS_EXTRFILESTOTEMP" fullword ascii
      $s19 = "s:IDS_READERROR" fullword ascii
      $s20 = "Please remove %s from %s folder. It is unsecure to run %s until it is done." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _d8bae33325cdfe4f3c47747a8bed89d753b58f470c8630ef1390784af3856636_ba2fdc59950c64afa4429a28ff4036f496e519a867c3182e322d78c0ee_12 {
   meta:
      description = "samples - from files d8bae33325cdfe4f3c47747a8bed89d753b58f470c8630ef1390784af3856636.exe, ba2fdc59950c64afa4429a28ff4036f496e519a867c3182e322d78c0eef27952.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d8bae33325cdfe4f3c47747a8bed89d753b58f470c8630ef1390784af3856636"
      hash2 = "ba2fdc59950c64afa4429a28ff4036f496e519a867c3182e322d78c0eef27952"
   strings:
      $s1 = "UrlMon" fullword ascii /* Goodware String - occured 30 times */
      $s2 = "SysUtils" fullword ascii /* Goodware String - occured 34 times */
      $s3 = "Background" fullword wide /* Goodware String - occured 153 times */
      $s4 = "3333f3333333" ascii /* Goodware String - occured 1 times */
      $s5 = " (%dx%d)" fullword wide /* Goodware String - occured 2 times */
      $s6 = "333DDD33333" ascii
      $s7 = "3333333383" ascii
      $s8 = "ExtActns" fullword ascii /* Goodware String - occured 5 times */
      $s9 = "ExtDlgs" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and ( all of them )
      ) or ( all of them )
}

rule _8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36_8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4_13 {
   meta:
      description = "samples - from files 8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36.exe, 8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943.exe, ee80038271164361a38cc49e3b1c1ee446eda1c80181ffe161307d414c55fcdf.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "8ba72f675acf5bc12805d4fff0bda437ea419d15e4237c916554a7f7df1b0b36"
      hash2 = "8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943"
      hash3 = "ee80038271164361a38cc49e3b1c1ee446eda1c80181ffe161307d414c55fcdf"
   strings:
      $s1 = "`[\\Ik:\\E" fullword ascii
      $s2 = "zTehhyx" fullword ascii
      $s3 = "uvqYI!)" fullword ascii
      $s4 = "rEjk+i0X" fullword ascii
      $s5 = "jATM6tEr[C" fullword ascii
      $s6 = "kswc!1" fullword ascii
      $s7 = "Wwckov<" fullword ascii
      $s8 = "EyhU%>dc" fullword ascii
      $s9 = "EiBt\\lj" fullword ascii
      $s10 = "}EcLBzzWM6" fullword ascii
      $s11 = "jomB1KC" fullword ascii
      $s12 = "S7DpMmk>!" fullword ascii
      $s13 = "hVnMElw:" fullword ascii
      $s14 = "KKjeXXKd" fullword ascii
      $s15 = "exdYc8e9" fullword ascii
      $s16 = "hlEZwvbG&" fullword ascii
      $s17 = "qWvDFGa" fullword ascii
      $s18 = "QJNsg{c" fullword ascii
      $s19 = "nXjj*Sg&&" fullword ascii
      $s20 = "ujjkT6]" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7_d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d_14 {
   meta:
      description = "samples - from files 35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7.exe, d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7"
      hash2 = "d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366"
   strings:
      $s1 = "3%3:3C3d3}3" fullword ascii /* hex encoded string '3<=3' */
      $s2 = "9 :;:J:d:\\;" fullword ascii
      $s3 = ":4:8:@:H:P:T:\\:p:" fullword ascii
      $s4 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii
      $s5 = "PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii
      $s6 = " -4HS8Q" fullword ascii
      $s7 = "1&111H1x1" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "343P3b3" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "9)989G9" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "7\"7.7:7" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "SUVWh`+C" fullword ascii
      $s12 = "=\"=3=8=M=" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "56;6F6K6P6n6" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "QSVWh`a@" fullword ascii
      $s15 = "5+555Q5\\5a5f5" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "URPQQh`.B" fullword ascii
      $s17 = "6:7T7n7" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "2*3:3Q3Y3" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "YPvUT#$WpWw" fullword ascii
      $s20 = "<%<4<B<" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394_327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a3_15 {
   meta:
      description = "samples - from files 7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394.exe, 327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba.exe, 6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394"
      hash2 = "327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba"
      hash3 = "6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599"
   strings:
      $s1 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\AppLaunch.exe" fullword wide
      $s2 = "ZAdedgr3" fullword ascii
      $s3 = "vjxhUisa1" fullword ascii
      $s4 = "cember" fullword ascii
      $s5 = "network reset" fullword ascii /* Goodware String - occured 567 times */
      $s6 = "network down" fullword ascii /* Goodware String - occured 567 times */
      $s7 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
      $s8 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
      $s9 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
      $s10 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
      $s11 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
      $s12 = "network unreachable" fullword ascii /* Goodware String - occured 569 times */
      $s13 = "host unreachable" fullword ascii /* Goodware String - occured 571 times */
      $s14 = "protocol error" fullword ascii /* Goodware String - occured 588 times */
      $s15 = "permission denied" fullword ascii /* Goodware String - occured 592 times */
      $s16 = "connection refused" fullword ascii /* Goodware String - occured 597 times */
      $s17 = "broken pipe" fullword ascii /* Goodware String - occured 635 times */
      $s18 = ":Jan:January:Feb:February:Mar:March:Apr:April:May:May:Jun:June:Jul:July:Aug:August:Sep:September:Oct:October:Nov:November:Dec:De" ascii
      $s19 = ".?AV_Iostream_error_category2@std@@" fullword ascii
      $s20 = "<xt <Xt" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926_215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc_16 {
   meta:
      description = "samples - from files 9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926.exe, 215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926"
      hash2 = "215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498"
   strings:
      $s1 = "get_encryptedPassword" fullword ascii
      $s2 = "set_encryptedPassword" fullword ascii
      $s3 = "_encryptedPassword" fullword ascii
      $s4 = "KeyLoggerEventArgsEventHandler" fullword ascii
      $s5 = "KeyLoggerEventArgs" fullword ascii
      $s6 = "get_logins" fullword ascii
      $s7 = "get_encryptedUsername" fullword ascii
      $s8 = "get_passwordField" fullword ascii
      $s9 = "get_timePasswordChanged" fullword ascii
      $s10 = "FFLogins" fullword ascii
      $s11 = "get_disabledHosts" fullword ascii
      $s12 = "_encryptedUsername" fullword ascii
      $s13 = "_passwordField" fullword ascii
      $s14 = "set_timePasswordChanged" fullword ascii
      $s15 = "Identifykey" fullword ascii
      $s16 = "timePasswordChanged" fullword ascii
      $s17 = "set_logins" fullword ascii
      $s18 = "set_passwordField" fullword ascii
      $s19 = "set_encryptedUsername" fullword ascii
      $s20 = "get_httprealm" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400_7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c6332842_17 {
   meta:
      description = "samples - from files f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400.exe, 7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400"
      hash2 = "7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1"
   strings:
      $s1 = "OrUo+ " fullword ascii
      $s2 = "XoYMgQ6" fullword ascii
      $s3 = "}MhqH?" fullword ascii
      $s4 = "ODZDzF/" fullword ascii
      $s5 = "t)vIxI.b2" fullword ascii
      $s6 = "PM@MdMdMdMdMdMdGdZ1" fullword ascii
      $s7 = "TGRx=QE" fullword ascii
      $s8 = "uETE~@l" fullword ascii
      $s9 = "ZkOh%Ih" fullword ascii
      $s10 = "XgBr0aa" fullword ascii
      $s11 = "\\@heqg" fullword ascii
      $s12 = "\\(1j8JZ" fullword ascii
      $s13 = "X\\,r#-Hh" fullword ascii
      $s14 = ";l0XyV" fullword ascii
      $s15 = "p9ZhYe" fullword ascii
      $s16 = ")UI')Sz" fullword ascii
      $s17 = ")o` DV_" fullword ascii
      $s18 = "8=IUzi" fullword ascii
      $s19 = "Oiyo9~" fullword ascii
      $s20 = ")wTC/]*" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394_327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a3_18 {
   meta:
      description = "samples - from files 7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394.exe, 327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba.exe, 2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2.exe, 23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b.exe, 6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394"
      hash2 = "327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba"
      hash3 = "2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2"
      hash4 = "23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b"
      hash5 = "6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599"
   strings:
      $s1 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s2 = "`template-parameter-" fullword ascii
      $s3 = "nullptr" fullword ascii
      $s4 = "regex_error(error_stack): There was insufficient memory to determine whether the regular expression could match the specified ch" ascii
      $s5 = "`generic-type-" fullword ascii
      $s6 = "aracter sequence." fullword ascii
      $s7 = "std::nullptr_t " fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b_dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f4_19 {
   meta:
      description = "samples - from files 5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b.exe, dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f432a0fd.exe, e842b6dff73f8cc125170bafb505357263972cefc0d7187207295a207a6a3bdf.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5ac2668fc54a07ebe5866fc08a924de42f3bdd5adfce8fb14889280678f9d98b"
      hash2 = "dd6d6790b18937e7f2ca0a99e4a7dca9a4f268aa3245ef319ba943d2f432a0fd"
      hash3 = "e842b6dff73f8cc125170bafb505357263972cefc0d7187207295a207a6a3bdf"
   strings:
      $s1 = "NYZYD49" fullword ascii
      $s2 = "lYZYX.?" fullword ascii
      $s3 = "NEFQP\"5" fullword ascii
      $s4 = "NEFP\\,=" fullword ascii
      $s5 = "NYZYX.=" fullword ascii
      $s6 = "NYZYX.<" fullword ascii
      $s7 = "OYZYX.=" fullword ascii
      $s8 = "NYkpk8Py" fullword ascii
      $s9 = "NFTgg&+" fullword ascii
      $s10 = "OYZYX.3" fullword ascii
      $s11 = "@EFQP\"5" fullword ascii
      $s12 = "NYZY_.:" fullword ascii
      $s13 = "@FXQP\"5" fullword ascii
      $s14 = "NYZYX~]n" fullword ascii
      $s15 = "NEFYX*=" fullword ascii
      $s16 = "NEFQP#3" fullword ascii
      $s17 = "NZDY^,=" fullword ascii
      $s18 = "NYZQP&5" fullword ascii
      $s19 = "nrviT\\ZYZ*;" fullword ascii
      $s20 = "NYZYZ*;" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7_1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de2_20 {
   meta:
      description = "samples - from files 35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7.exe, 1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715.exe, d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7"
      hash2 = "1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715"
      hash3 = "d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366"
   strings:
      $s1 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" fullword ascii
      $s2 = "$GETPASSWORD1:SIZE" fullword ascii
      $s3 = "$GETPASSWORD1:IDOK" fullword ascii
      $s4 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii
      $s5 = "      <requestedExecutionLevel level=\"asInvoker\"            " fullword ascii
      $s6 = "s:IDS_ERRLNKTARGET" fullword ascii
      $s7 = "$GETPASSWORD1:IDCANCEL" fullword ascii
      $s8 = "$GETPASSWORD1:CAPTION" fullword ascii
      $s9 = "s:IDS_WRONGFILEPASSWORD" fullword ascii
      $s10 = "s:IDS_WRONGPASSWORD" fullword ascii
      $s11 = "s:IDS_MAINHEADERBROKEN" fullword ascii
      $s12 = "s:IDS_HEADERBROKEN" fullword ascii
      $s13 = "s:IDS_COPYERROR" fullword ascii
      $s14 = "vuOuefweV$y" fullword ascii
      $s15 = "$ASKNEXTVOL:IDC_NEXTVOLFIND" fullword ascii
      $s16 = "$ASKNEXTVOL:SIZE" fullword ascii
      $s17 = "s:IDS_UNKENCMETHOD" fullword ascii
      $s18 = "$ASKNEXTVOL:IDC_NEXTVOLINFO2" fullword ascii
      $s19 = "s:IDS_TITLE1A" fullword ascii
      $s20 = "|$,;|$8" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0f04730f576ba9c455a7c3f03774cb9823210e728fac4674cf9f5d147a0149ef_c0de3820d44c7aebc56f12be217cab5c5b758344750e73e1288f42e0f3_21 {
   meta:
      description = "samples - from files 0f04730f576ba9c455a7c3f03774cb9823210e728fac4674cf9f5d147a0149ef.exe, c0de3820d44c7aebc56f12be217cab5c5b758344750e73e1288f42e0f373f038.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "0f04730f576ba9c455a7c3f03774cb9823210e728fac4674cf9f5d147a0149ef"
      hash2 = "c0de3820d44c7aebc56f12be217cab5c5b758344750e73e1288f42e0f373f038"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
      $x2 = "win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"x86\" publicKeyToken=\"6595b64144" ascii
      $s3 = "requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivile" ascii
      $s4 = "ZDovZmlsZTEudHh0" fullword ascii /* base64 encoded string 'd:/file1.txt' */
      $s5 = "SW5kaWEgU3RhbmRhcmQgVGltZQ==" fullword ascii /* base64 encoded string 'India Standard Time' */
      $s6 = "MiA9IHswfQ==" fullword ascii /* base64 encoded string '2 = {0}' */
      $s7 = "MSA9IHswfQ==" fullword ascii /* base64 encoded string '1 = {0}' */
      $s8 = "U1c1MmIydGw=" fullword ascii /* base64 encoded string 'SW52b2tl' */
      $s9 = "ZG1KakxtVjRaUT09" fullword ascii /* base64 encoded string 'dmJjLmV4ZQ==' */
      $s10 = "VGljayBDb3VudDog" fullword ascii /* base64 encoded string 'Tick Count: ' */
      $s11 = "RHluYW1pY0RsbEludm9rZVR5cGU=" fullword ascii /* base64 encoded string 'DynamicDllInvokeType' */
      $s12 = "VW1WemRXMWxWR2h5WldGaw==" fullword ascii /* base64 encoded string 'UmVzdW1lVGhyZWFk' */
      $s13 = "SW5kaWEgU3RhbmRhcmQgVGltZTog" fullword ascii /* base64 encoded string 'India Standard Time: ' */
      $s14 = "aHR0cDpkb3RuZXRwZXJscy1jb20=" fullword ascii /* base64 encoded string 'http:dotnetperls-com' */
      $s15 = "CreateGetStringDelegate" fullword ascii
      $s16 = "+.+3+4+5+:~2" fullword ascii /* hex encoded string '4R' */
      $s17 = "gdsadffjfagg" fullword ascii
      $s18 = "hkgfffdffdhdrfdfdfdsshcf" fullword ascii
      $s19 = "sfdsdffs" fullword ascii
      $s20 = "hsgfffdd" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba_6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bc_22 {
   meta:
      description = "samples - from files 327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba.exe, 6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba"
      hash2 = "6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599"
   strings:
      $s1 = "0 0$080@0D0L0d0|0" fullword ascii /* Goodware String - occured 1 times */
      $s2 = ":$:<:T:X:l:t:x:|:" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "=(=@=X=\\=p=x=|=" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "8 848<8@8H8`8x8|8" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "8$8,888`8h8t8" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "?(?,?@?H?L?T?l?" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "?(?H?t?" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "<4<8<L<T<X<\\<d<|<" fullword ascii
      $s9 = "7,7D7H7\\7d7h7l7p7t7" fullword ascii
      $s10 = "?$?(?,?0?4?@?X?p?t?" fullword ascii
      $s11 = "0 080<0P0X0\\0`0d0h0l0x0" fullword ascii
      $s12 = "6(6,6064686<6D6H6L6P6T6X6`6d6h6l6p6t6x6|6" fullword ascii
      $s13 = "9,9D9H9\\9d9h9l9p9x9" fullword ascii
      $s14 = ";$>,>4><>D>L>T>\\>d>l>t>|>" fullword ascii
      $s15 = "= =$=(=,=0=H=L=`=h=l=p=t=x=|=" fullword ascii
      $s16 = "2$2<2@2T2X2l2t2|2" fullword ascii
      $s17 = "343L3P3d3l3p3t3|3" fullword ascii
      $s18 = "j@h4OP" fullword ascii
      $s19 = "3L5P5X5\\58>h>" fullword ascii
      $s20 = "6$6,6064686@6X6p6t6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc_2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210_23 {
   meta:
      description = "samples - from files 0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc.exe, 2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc"
      hash2 = "2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6"
   strings:
      $s1 = "xmscoree.dll" fullword wide
      $s2 = "D:\\Mktmp\\Amadey\\Release\\Amadey.pdb" fullword ascii
      $s3 = "@api-ms-win-core-synch-l1-2-0.dll" fullword wide
      $s4 = "WPWWWS" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "WWWSHSh" fullword ascii
      $s6 = "Bapi-ms-win-core-fibers-l1-1-1" fullword wide
      $s7 = "Bapi-ms-win-core-datetime-l1-1-1" fullword wide
      $s8 = ";1#INF" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "7(7,7074787<7@7D7" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "?7?A?K?b?l?" fullword ascii
      $s11 = "5!5+5B5L5w5" fullword ascii
      $s12 = "070A0K0b0l0" fullword ascii
      $s13 = "=!=+=B=L=w=" fullword ascii
      $s14 = "2G3`3l3" fullword ascii
      $s15 = "6!6+6B6L6w6" fullword ascii
      $s16 = "CM @PRj" fullword ascii
      $s17 = "979A9K9b9l9" fullword ascii
      $s18 = ";!;+;B;L;w;" fullword ascii
      $s19 = "373A3K3b3l3" fullword ascii
      $s20 = "<\"<,<W<a<k<" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f_b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd_24 {
   meta:
      description = "samples - from files b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f.exe, b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26.exe, f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f"
      hash2 = "b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26"
      hash3 = "f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f"
   strings:
      $s1 = " System.Globalization.CompareInfo" fullword ascii
      $s2 = " System.Globalization.SortVersion" fullword ascii
      $s3 = " System.Globalization.CultureInfo" fullword ascii
      $s4 = "TextBox1" fullword wide
      $s5 = "PictureBox3" fullword wide
      $s6 = "CheckBox1" fullword wide
      $s7 = "Label10" fullword wide
      $s8 = "PictureBox1" fullword wide
      $s9 = "ListBox1" fullword wide /* Goodware String - occured 1 times */
      $s10 = "ListBox2" fullword wide /* Goodware String - occured 1 times */
      $s11 = "Label6" fullword wide
      $s12 = "Label4" fullword wide
      $s13 = "Label7" fullword wide
      $s14 = "Label9" fullword wide
      $s15 = "PADPADPa" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "Label8" fullword wide
      $s17 = "Label5" fullword wide
      $s18 = "Label3" fullword wide
      $s19 = "b77a5c561934e089f" ascii
      $s20 = "Label2" fullword wide /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e_c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9_25 {
   meta:
      description = "samples - from files 09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e.exe, c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19.exe, b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c.exe, 7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394.exe, 46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2.exe, 149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443.exe, 9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252.exe, 327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba.exe, 258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec.exe, e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161.exe, 215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779.exe, b008e6b92de9b7d2e18fe2712c1c0f2d86fbe86e70093e4c54c490161818992c.exe, 02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241.exe, 3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93.exe, 0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc.exe, b048a1bfca1c0f1a364faeef88c9decda4fa71a66e3dd3225abe70e267b0b36b.exe, bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5.exe, 2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2.exe, 2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6.exe, b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193.exe, 7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38.exe, fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be.exe, 8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218.exe, 35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7.exe, 0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e.exe, 5df688f5538aca79256dc329400ac5fb412000930d21072433733fa8417b9913.exe, 60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d.exe, 23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b.exe, 1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715.exe, 6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599.exe, d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366.exe, 8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f.exe, a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e"
      hash2 = "c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19"
      hash3 = "b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c"
      hash4 = "7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394"
      hash5 = "46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2"
      hash6 = "149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443"
      hash7 = "9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252"
      hash8 = "327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba"
      hash9 = "258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec"
      hash10 = "e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161"
      hash11 = "215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779"
      hash12 = "b008e6b92de9b7d2e18fe2712c1c0f2d86fbe86e70093e4c54c490161818992c"
      hash13 = "02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241"
      hash14 = "3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93"
      hash15 = "0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc"
      hash16 = "b048a1bfca1c0f1a364faeef88c9decda4fa71a66e3dd3225abe70e267b0b36b"
      hash17 = "bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5"
      hash18 = "2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2"
      hash19 = "2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6"
      hash20 = "b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193"
      hash21 = "7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38"
      hash22 = "fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be"
      hash23 = "8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218"
      hash24 = "35e349621ddf050a9abb0ea7fa30b16c0a4dbf1c9f367eb613865d51f989b0d7"
      hash25 = "0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e"
      hash26 = "5df688f5538aca79256dc329400ac5fb412000930d21072433733fa8417b9913"
      hash27 = "60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d"
      hash28 = "23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b"
      hash29 = "1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715"
      hash30 = "6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599"
      hash31 = "d6a373eb8f771884afc984fba23ff81b034146282f9285e5beaf5eb31d886366"
      hash32 = "8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f"
      hash33 = "a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = " Base Class Descriptor at (" fullword ascii
      $s3 = " Class Hierarchy Descriptor'" fullword ascii
      $s4 = " Complete Object Locator'" fullword ascii
      $s5 = " delete[]" fullword ascii
      $s6 = " delete" fullword ascii
      $s7 = " new[]" fullword ascii
      $s8 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e_c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9_26 {
   meta:
      description = "samples - from files 09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e.exe, c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19.exe, b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c.exe, 46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2.exe, 149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443.exe, 258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec.exe, e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161.exe, 215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779.exe, 02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241.exe, 3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93.exe, b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193.exe, fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be.exe, 8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218.exe, 0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e.exe, 60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d.exe, a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e"
      hash2 = "c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19"
      hash3 = "b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c"
      hash4 = "46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2"
      hash5 = "149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443"
      hash6 = "258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec"
      hash7 = "e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161"
      hash8 = "215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779"
      hash9 = "02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241"
      hash10 = "3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93"
      hash11 = "b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193"
      hash12 = "fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be"
      hash13 = "8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218"
      hash14 = "0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e"
      hash15 = "60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d"
      hash16 = "a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a"
   strings:
      $s1 = "_Rarip bopetevutuhu farat jetuhavowu dojucubapor nosijoyosajudow yahotahufedejuc pegiregelukuwax" fullword wide
      $s2 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" fullword ascii
      $s3 = "bdqddqdq" fullword ascii
      $s4 = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" fullword ascii
      $s5 = "fifinaboriyogadideyip" fullword wide
      $s6 = "muluviletakajiduzor" fullword wide
      $s7 = "yacudas" fullword wide
      $s8 = "fihodavinebelocekoxigaliwelec" fullword wide
      $s9 = "vaxozaboxuwucurexilijebonuxegid" fullword wide
      $s10 = "degevoronaxefayojabisehucuyinaz" fullword wide
      $s11 = "katuwoxetohoditobizajobecohisel fivamowareweh sobogoyanahinelaloyifuyazo" fullword ascii
      $s12 = "13.78.85.48" fullword wide
      $s13 = "Lucufiyelofopi" fullword wide
      $s14 = "Monamavigula" fullword wide
      $s15 = "Gisoxofohu" fullword wide
      $s16 = "mjjjmx" fullword ascii
      $s17 = "zzzzzzzz|" fullword ascii
      $s18 = "+~~~~~~~~eYYYYY" fullword ascii
      $s19 = "WWQQQzz" fullword ascii
      $s20 = "/)ttttttttttttttttttttttttttt" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d6a1a23efa1aa9e632f9e111e21070f0390678592d94fc75370d4325f45cf5d7_ebdc54df582be1cafb91a1948657212fe50229b09071b1cbb3d1b660cc_27 {
   meta:
      description = "samples - from files d6a1a23efa1aa9e632f9e111e21070f0390678592d94fc75370d4325f45cf5d7.exe, ebdc54df582be1cafb91a1948657212fe50229b09071b1cbb3d1b660cc707fc5.exe, 37a6ef95815119e73613aa856f88a70ace7ce8dffa6e0b131b6f148f2dd37fc8.exe, d4163f1179d58f842ba3b9cd28cd315de031669b93d87111c40fbc13167e42ab.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d6a1a23efa1aa9e632f9e111e21070f0390678592d94fc75370d4325f45cf5d7"
      hash2 = "ebdc54df582be1cafb91a1948657212fe50229b09071b1cbb3d1b660cc707fc5"
      hash3 = "37a6ef95815119e73613aa856f88a70ace7ce8dffa6e0b131b6f148f2dd37fc8"
      hash4 = "d4163f1179d58f842ba3b9cd28cd315de031669b93d87111c40fbc13167e42ab"
   strings:
      $s1 = "C:\\Windows\\System32\\Werfault.exe" fullword wide
      $s2 = "C:\\Windows\\SysWOW64\\Werfault.exe" fullword wide
      $s3 = "AWAVAUA" fullword ascii /* reversed goodware string 'AUAVAWA' */
      $s4 = "/test.txt" fullword wide
      $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36" fullword wide
      $s6 = "X-Havoc-Agent: Demon" fullword wide
      $s7 = "/helloworld.js" fullword wide
      $s8 = "/index.php" fullword wide
      $s9 = "AVAUATI" fullword ascii
      $s10 = "AVAUATA" fullword ascii
      $s11 = "AWAVAUATL" fullword ascii
      $s12 = "AVAUATWVSL" fullword ascii
      $s13 = "AWAVAUI" fullword ascii
      $s14 = "AWAVAUATI" fullword ascii
      $s15 = "157.245.47.66" fullword wide
      $s16 = "AWAVAUATU1" fullword ascii
      $s17 = "AWAVAUE1" fullword ascii
      $s18 = "AVAUATE1" fullword ascii
      $s19 = "l$hA9}" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "_A\\A]A^" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c_e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405_28 {
   meta:
      description = "samples - from files b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c.exe, e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161.exe, 215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779.exe, 02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241.exe, fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be.exe, 8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218.exe, 60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c"
      hash2 = "e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161"
      hash3 = "215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779"
      hash4 = "02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241"
      hash5 = "fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be"
      hash6 = "8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218"
      hash7 = "60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d"
   strings:
      $s1 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s2 = "sqpzzpzzpzzpzzpzzpzzpzzz" fullword ascii
      $s3 = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn" fullword ascii
      $s4 = "yyyyyyyyyyyyy?" fullword ascii
      $s5 = "WWEyyyyyyyyy" fullword ascii
      $s6 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAAZ\"" fullword ascii
      $s7 = "vvvvvvvvvvvX(+" fullword ascii
      $s8 = "EEEEEEy" fullword ascii
      $s9 = "rtTyB?<t" fullword ascii
      $s10 = "tttttt<<<" fullword ascii
      $s11 = "/99AAAAAAAAAAAAAAAAA" fullword ascii
      $s12 = "sssssssssssfsfsffff{k" fullword ascii
      $s13 = "99AAAAAAAAAAAAAAAAA" ascii
      $s14 = "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{TTTTTTTTTTTTTTTTW" fullword ascii
      $s15 = "sssssfsssss{k" fullword ascii
      $s16 = "Tyr<?tEWEWWWWWyT?<?By" fullword ascii
      $s17 = "AAAAAAAAAAAAAAAAAAAAe99999999e9AAAA" ascii
      $s18 = " ssssssss%" fullword ascii
      $s19 = "sqzz&1@@@@@@@@@@@@@@@@@@@@@@@@@@@1zzz&s" fullword ascii
      $s20 = "zzzzzzzzzzzzzzzzzzzzzzzzzz&zz&s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f_091245bf789aabbefd2a412d39aeddec596c8b71aa93fdb4eb1c7b7d38_29 {
   meta:
      description = "samples - from files b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f.exe, 091245bf789aabbefd2a412d39aeddec596c8b71aa93fdb4eb1c7b7d38ed3f90.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f"
      hash2 = "091245bf789aabbefd2a412d39aeddec596c8b71aa93fdb4eb1c7b7d38ed3f90"
   strings:
      $s1 = "nativeEntry" fullword ascii
      $s2 = "$$method0x6000007-1" fullword ascii
      $s3 = "$$method0x6000039-1" fullword ascii
      $s4 = "$$method0x600005f-1" fullword ascii
      $s5 = "classthis" fullword ascii
      $s6 = "$$method0x600002a-1" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "$$method0x6000020-1" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "nativeSizeOfCode" fullword ascii
      $s9 = "$$method0x600002a-2" fullword ascii
      $s10 = "$$method0x6000020-2" fullword ascii
      $s11 = "GetDelegateForFunctionPointer" fullword wide /* Goodware String - occured 1 times */
      $s12 = "$$method0x600027b-1" fullword ascii /* Goodware String - occured 4 times */
      $s13 = "{11111-22222-10009-11112}" fullword wide
      $s14 = "{11111-22222-50001-00000}" fullword wide
      $s15 = "{11111-22222-20001-00001}" fullword wide
      $s16 = "{11111-22222-20001-00002}" fullword wide
      $s17 = "{11111-22222-30001-00001}" fullword wide
      $s18 = "{11111-22222-30001-00002}" fullword wide
      $s19 = "{11111-22222-40001-00001}" fullword wide
      $s20 = "{11111-22222-40001-00002}" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _d440158b91d965693007b539131704b3bdd72e864b5adc1c0e230213acd3d97b_09571623326972119f44c4f2e92b7dc4ef670a9238d21c4fbc671269da_30 {
   meta:
      description = "samples - from files d440158b91d965693007b539131704b3bdd72e864b5adc1c0e230213acd3d97b.exe, 09571623326972119f44c4f2e92b7dc4ef670a9238d21c4fbc671269da610ae5.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d440158b91d965693007b539131704b3bdd72e864b5adc1c0e230213acd3d97b"
      hash2 = "09571623326972119f44c4f2e92b7dc4ef670a9238d21c4fbc671269da610ae5"
   strings:
      $s1 = "EncryptOrDecryptXOR" fullword ascii
      $s2 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" fullword wide /* base64 encoded string 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' */
      $s3 = "Select * from Win32_ComputerSystem" fullword wide
      $s4 = "enableFakeError" fullword ascii
      $s5 = "vmware" fullword wide
      $s6 = "EncryptInitalize" fullword ascii
      $s7 = "encryptType" fullword ascii
      $s8 = "<EncryptOutput>b__2" fullword ascii
      $s9 = "EncryptOutput" fullword ascii
      $s10 = "<EncryptInitalize>b__0" fullword ascii
      $s11 = "hyoeudoi" fullword wide
      $s12 = "yoeudoi" fullword wide
      $s13 = "runType" fullword ascii
      $s14 = "fileRunTypes" fullword ascii
      $s15 = "b3knqa5jv4o.resources" fullword ascii
      $s16 = "ZMHYOEUDOI" fullword wide
      $s17 = "fileDropPaths" fullword ascii
      $s18 = "microsoft corporation" fullword wide
      $s19 = "oeudoi0" fullword wide
      $s20 = "fileTypes" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a521_31 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74.exe, fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af.exe, 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe, 5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5.exe, f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400.exe, 582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f.exe, 7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1.exe, dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe, f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe, df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74"
      hash3 = "fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af"
      hash4 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash5 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash6 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
      hash7 = "5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5"
      hash8 = "f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400"
      hash9 = "582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f"
      hash10 = "7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1"
      hash11 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
      hash12 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
      hash13 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
      hash14 = "f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48"
      hash15 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
      hash16 = "df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1"
   strings:
      $s1 = "343^3}3" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "<A<Y<u<" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "11.00.17763.1 (WinBuild.160101.0800)" fullword wide
      $s4 = ">0>6><>B>H>N>U>\\>c>j>q>x>" fullword ascii /* Goodware String - occured 2 times */
      $s5 = "1b2m2s2" fullword ascii /* Goodware String - occured 2 times */
      $s6 = ":G:_:d:" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "1,1Q1_1t1" fullword ascii
      $s8 = "8+888_8p8" fullword ascii
      $s9 = "5!5,5:5Y5b5" fullword ascii
      $s10 = "5.5=5N5W5" fullword ascii
      $s11 = "1#1<1E1U1[1g1l1" fullword ascii
      $s12 = "6\"6(636:6G6N6S6a6o6" fullword ascii
      $s13 = "0*040>0" fullword ascii
      $s14 = ">)?5?A?X?" fullword ascii
      $s15 = "2$212R2X2c2j2u2" fullword ascii
      $s16 = ";#<)<E<V<h<z<" fullword ascii
      $s17 = ":!:&:,:1:6:;:@:F:N:m:" fullword ascii
      $s18 = "8F9Z9k9" fullword ascii
      $s19 = "6%6*61696>6j6s6" fullword ascii
      $s20 = "1*2A2`2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5_5df688f5538aca79256dc329400ac5fb412000930d21072433733fa841_32 {
   meta:
      description = "samples - from files bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5.exe, 5df688f5538aca79256dc329400ac5fb412000930d21072433733fa8417b9913.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5"
      hash2 = "5df688f5538aca79256dc329400ac5fb412000930d21072433733fa8417b9913"
   strings:
      $s1 = "T$h9T$" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "D$<RSP" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "L$PQSV" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide
      $s5 = "ForceRemove" fullword ascii /* Goodware String - occured 1167 times */
      $s6 = "NoRemove" fullword ascii /* Goodware String - occured 1170 times */
      $s7 = "FL9~Xu" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "D$HUWP" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "t.9Vlt)" fullword ascii /* Goodware String - occured 2 times */
      $s10 = ";l$TsY)l$T" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "L$4;D$Ts<)D$T" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "~Rich,q" fullword ascii
      $s13 = "t*9Qlu%" fullword ascii /* Goodware String - occured 4 times */
      $s14 = "uL9=\\9B" fullword ascii
      $s15 = "v$;540B" fullword ascii
      $s16 = "t$H;t$8" fullword ascii
      $s17 = "Oh;O\\sN" fullword ascii
      $s18 = "~2#{~-q" fullword ascii
      $s19 = "t:<wuE" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af_17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd0_33 {
   meta:
      description = "samples - from files fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af.exe, 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af"
      hash2 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
   strings:
      $s1 = "QANL*8N" fullword ascii
      $s2 = "MwGM\\4]9L" fullword ascii
      $s3 = "\\+GpEwW" fullword ascii
      $s4 = "\\g,+xa" fullword ascii
      $s5 = "\\=<a+]" fullword ascii
      $s6 = "hwF;6g" fullword ascii
      $s7 = "SRhvig" fullword ascii
      $s8 = "$]J^]?" fullword ascii
      $s9 = ":z!\\|\"g" fullword ascii
      $s10 = ">M*@nV" fullword ascii
      $s11 = "i1L0%." fullword ascii
      $s12 = "IK6\\MI" fullword ascii
      $s13 = "0^9;Rk" fullword ascii
      $s14 = "@Ia<zW" fullword ascii
      $s15 = "XWG$w!m" fullword ascii
      $s16 = "<7+aSP" fullword ascii
      $s17 = "ZeiqXA" fullword ascii
      $s18 = "Nz32Qx" fullword ascii
      $s19 = "qkyVN`" fullword ascii
      $s20 = "NT,#T6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a_bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1e_34 {
   meta:
      description = "samples - from files 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash2 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
   strings:
      $s1 = "UIZpST+" fullword ascii
      $s2 = ".FUbu?|" fullword ascii
      $s3 = "=sthfn?" fullword ascii
      $s4 = "CrjXSM'" fullword ascii
      $s5 = "KOef75" fullword ascii
      $s6 = "+!\"rzAh" fullword ascii
      $s7 = "5x]%Bn>" fullword ascii
      $s8 = ":jAxvK" fullword ascii
      $s9 = "U:I9j\\6" fullword ascii
      $s10 = "X.+io\"" fullword ascii
      $s11 = "X9]332" fullword ascii
      $s12 = "/$wl 2" fullword ascii
      $s13 = "XJa@[C#" fullword ascii
      $s14 = "AUn~oH" fullword ascii
      $s15 = "&0uUB5" fullword ascii
      $s16 = " iX_(8[" fullword ascii
      $s17 = "L^Ww]6" fullword ascii
      $s18 = "m3gB\"s+z" fullword ascii
      $s19 = "jmX%E~" fullword ascii
      $s20 = "3k-s(l" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e_c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9_35 {
   meta:
      description = "samples - from files 09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e.exe, c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19.exe, b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c.exe, 46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2.exe, 149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443.exe, 258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec.exe, e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161.exe, 215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779.exe, 02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241.exe, 3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93.exe, b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193.exe, 7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38.exe, fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be.exe, 8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218.exe, 0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e.exe, 60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d.exe, a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e"
      hash2 = "c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19"
      hash3 = "b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c"
      hash4 = "46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2"
      hash5 = "149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443"
      hash6 = "258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec"
      hash7 = "e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161"
      hash8 = "215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779"
      hash9 = "02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241"
      hash10 = "3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93"
      hash11 = "b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193"
      hash12 = "7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38"
      hash13 = "fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be"
      hash14 = "8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218"
      hash15 = "0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e"
      hash16 = "60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d"
      hash17 = "a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a"
   strings:
      $s1 = "FileDescriptions" fullword wide
      $s2 = "PlasticFantastic" fullword wide
      $s3 = "LegalCopyrights" fullword wide
      $s4 = "Challangers kenia" fullword wide
      $s5 = "029385B1" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd0_36 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe, 582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash3 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash4 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
      hash5 = "582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f"
      hash6 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
      hash7 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
      hash8 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "azvhin" fullword ascii
      $s2 = "v\\* p!" fullword ascii
      $s3 = "ksew5\\" fullword ascii
      $s4 = "pXuoZ}J" fullword ascii
      $s5 = "+kemuPO%L=" fullword ascii
      $s6 = "[7EUUTTEEU" fullword ascii
      $s7 = "$KjqqBN!I$" fullword ascii
      $s8 = "CdFFE3" ascii
      $s9 = "h+;Ozv" fullword ascii
      $s10 = "Nd%cvg" fullword ascii
      $s11 = "9}G1@KK" fullword ascii
      $s12 = "c~h4-$(" fullword ascii
      $s13 = "9Ft$A }" fullword ascii
      $s14 = "!y?(KD " fullword ascii
      $s15 = "q|),Bn" fullword ascii
      $s16 = "'(ypt':A" fullword ascii
      $s17 = "z2|Dv)" fullword ascii
      $s18 = "ces{3U" fullword ascii
      $s19 = "\"p|qk$j" fullword ascii
      $s20 = "u!Kx#E" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f_bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1e_37 {
   meta:
      description = "samples - from files dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
      hash2 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
   strings:
      $s1 = ".inS|:" fullword ascii
      $s2 = "JXnZsE[" fullword ascii
      $s3 = "\"fCnd?" fullword ascii
      $s4 = "\\IvM G" fullword ascii
      $s5 = "\"2> 44" fullword ascii
      $s6 = "{^8TPB" fullword ascii
      $s7 = "w{;{J]u9" fullword ascii
      $s8 = "}Zj0)8e" fullword ascii
      $s9 = ";)xt}4" fullword ascii
      $s10 = "]m\"JJt" fullword ascii
      $s11 = "V:*\"9\"" fullword ascii
      $s12 = "Ri95667)" fullword ascii
      $s13 = "Ek&w1l" fullword ascii
      $s14 = "*}Sc)kj" fullword ascii
      $s15 = "\"Q6+$7" fullword ascii
      $s16 = "=Hes=on" fullword ascii
      $s17 = "W0Sqss" fullword ascii
      $s18 = "G#S~2qc" fullword ascii
      $s19 = "d3;S+I" fullword ascii
      $s20 = "U}ezlZ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c_e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405_38 {
   meta:
      description = "samples - from files b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c.exe, e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161.exe, 215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779.exe, 7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38.exe, fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be.exe, 8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218.exe, 60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b4d16c2fc236efc013f248a71bfae9854bd54265ed7ec7039dd3941303aa5c2c"
      hash2 = "e4e4ba94f26c1684ca0d8815d9f20b81e3c7000a88729a460f688ef405995161"
      hash3 = "215517d2296fb92910d59ad3a6fbced4e839c62d97cc06d8985a1768f8068779"
      hash4 = "7f1f582a1cd4d1883aef63d5f73b7cc514e3c9c3671c3c959b0f4964fdb52e38"
      hash5 = "fbbe56d38e86e597d6ebbf7105ba7fbe4ba0ee651778895c6ed40c2498cc09be"
      hash6 = "8189c1c7f01185fd55c619bf4ae7fbc49126d649423c4421ad1085248484c218"
      hash7 = "60232c2f40d59f3c48dfc9c3e5d70941ccdc99b6e735b6aaeba919ff20d0632d"
   strings:
      $s1 = "D$09\\$Ds" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "F@9n8u" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "D$0VUP" fullword ascii /* Goodware String - occured 4 times */
      $s4 = "Fh=`3B" fullword ascii
      $s5 = "vL;5d<B" fullword ascii
      $s6 = "u}hl7@" fullword ascii
      $s7 = "L$$QRRf" fullword ascii
      $s8 = "t$@9\\$Ds" fullword ascii
      $s9 = "v4;5L<B" fullword ascii
      $s10 = "T$(RWWW" fullword ascii
      $s11 = "T$`RPP" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d8_39 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
   strings:
      $s1 = "BJ)+ Q" fullword ascii
      $s2 = "RzlKS!" fullword ascii
      $s3 = "addb.|>2" fullword ascii
      $s4 = "OZBGDG" fullword ascii
      $s5 = "('I([[" fullword ascii
      $s6 = "dr]-ij" fullword ascii
      $s7 = "&CNg|iS" fullword ascii
      $s8 = "^wWq6zk" fullword ascii
      $s9 = "0^17Nk" fullword ascii
      $s10 = "rE<~vt" fullword ascii
      $s11 = "S3HImq" fullword ascii
      $s12 = ")]zl@`" fullword ascii
      $s13 = "g{= 3O" fullword ascii
      $s14 = "l^]+l9/" fullword ascii
      $s15 = "(O1d&]hfe" fullword ascii
      $s16 = "=t7~f>" fullword ascii
      $s17 = "Ey7|8k" fullword ascii
      $s18 = "0Dx0&C" fullword ascii
      $s19 = "N(H,DP" fullword ascii
      $s20 = "^U?$OEC" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252_1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de2_40 {
   meta:
      description = "samples - from files 9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252.exe, 1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252"
      hash2 = "1ee660ee24030f3bef36495ab2f47c7a05c9796ebad4105e649f2f5de284f715"
   strings:
      $s1 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s2 = "%The archive comment header is corrupt" fullword wide
      $s3 = "ErroraErrors encountered while performing the operation" fullword wide
      $s4 = "Please download a fresh copy and retry the installation" fullword wide
      $s5 = "Security warningKPlease remove %s from folder %s. It is unsecure to run %s until it is done." fullword wide
      $s6 = "Skipping %s" fullword wide
      $s7 = "File close error" fullword wide
      $s8 = "=Total path and file name length must not exceed %d characters" fullword wide
      $s9 = "folder is not accessible" fullword wide
      $s10 = "Extracting %s" fullword wide /* Goodware String - occured 2 times */
      $s11 = "WinRAR self-extracting archive" fullword wide
      $s12 = "&Destination folder" fullword wide
      $s13 = "Confirm file replace" fullword wide /* Goodware String - occured 1 times */
      $s14 = "The following file already exists" fullword wide /* Goodware String - occured 1 times */
      $s15 = "Rename file" fullword wide /* Goodware String - occured 1 times */
      $s16 = "Select destination folder" fullword wide
      $s17 = "Unexpected end of archiveThe file \"%s\" header is corrupt" fullword wide /* Goodware String - occured 1 times */
      $s18 = "The required volume is absent" fullword wide
      $s19 = "2The archive is either in unknown format or damaged" fullword wide
      $s20 = "Next volume" fullword wide /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f_1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965a_41 {
   meta:
      description = "samples - from files b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f.exe, 1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f"
      hash2 = "1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3"
   strings:
      $s1 = "Button9" fullword wide
      $s2 = "Button12" fullword wide
      $s3 = "Button10" fullword wide
      $s4 = "Button16" fullword wide
      $s5 = "Button15" fullword wide
      $s6 = "Button13" fullword wide
      $s7 = "Button14" fullword wide
      $s8 = "Button18" fullword wide
      $s9 = "Button11" fullword wide
      $s10 = "Button6" fullword wide /* Goodware String - occured 2 times */
      $s11 = "Button7" fullword wide /* Goodware String - occured 2 times */
      $s12 = "Button5" fullword wide /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af_f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6_42 {
   meta:
      description = "samples - from files fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af.exe, f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af"
      hash2 = "f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48"
   strings:
      $s1 = "RxANR_3" fullword ascii
      $s2 = "xgQV+-c" fullword ascii
      $s3 = "I5klOdh" fullword ascii
      $s4 = "/~.!06k&" fullword ascii
      $s5 = "Kof6't" fullword ascii
      $s6 = "vXw(Wr" fullword ascii
      $s7 = "q1{X[H" fullword ascii
      $s8 = "TJlTTI" fullword ascii
      $s9 = "1![1~p" fullword ascii
      $s10 = "AYQMnM" fullword ascii
      $s11 = "ymy(qg" fullword ascii
      $s12 = "._@wrU" fullword ascii
      $s13 = "oX`};p" fullword ascii
      $s14 = "=6o-_A(+" fullword ascii
      $s15 = "RX`U6qf@" fullword ascii
      $s16 = "2.2V2c2l2" fullword ascii
      $s17 = "],O7(9" fullword ascii
      $s18 = "5f}^Gk" fullword ascii
      $s19 = "LVc-Mt" fullword ascii
      $s20 = "u{dx[i" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f_2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11_43 {
   meta:
      description = "samples - from files b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f.exe, 2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f"
      hash2 = "2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2"
   strings:
      $s1 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii
      $s2 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii
      $s3 = " Microsoft Operations Puerto Rico1&0$" fullword ascii
      $s4 = "3http://www.microsoft.com/pkiops/Docs/Repository.htm0" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "100706204017" ascii
      $s6 = "210930182225" ascii
      $s7 = "as.,k{n?," fullword ascii
      $s8 = "210930182225Z" fullword ascii
      $s9 = "300930183225" ascii
      $s10 = "300930183225Z0|1" fullword ascii
      $s11 = "250706205017" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072_8a09e86a04a6dbd37f88d21e450d3072d11f24ba2c2f3f724383859f89_44 {
   meta:
      description = "samples - from files a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072.exe, 8a09e86a04a6dbd37f88d21e450d3072d11f24ba2c2f3f724383859f89a3424c.exe, 566dba1fe1103869980a78a3e18e3d62e2be44935a27c825024f94fe56d7be7b.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072"
      hash2 = "8a09e86a04a6dbd37f88d21e450d3072d11f24ba2c2f3f724383859f89a3424c"
      hash3 = "566dba1fe1103869980a78a3e18e3d62e2be44935a27c825024f94fe56d7be7b"
   strings:
      $x1 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>Nu" ascii
      $s2 = "CRYPTBASE" fullword ascii
      $s3 = "PROPSYS" fullword ascii
      $s4 = "APPHELP" fullword ascii
      $s5 = "UXTHEME" fullword ascii
      $s6 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s7 = "SHFOLDER" fullword ascii /* Goodware String - occured 37 times */
      $s8 = "SETUPAPI" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "CLBCATQ" fullword ascii
      $s10 = "USERENV" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "Vj%SSS" fullword ascii
      $s12 = "OLEACC" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394_bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28a_45 {
   meta:
      description = "samples - from files 7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394.exe, bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5.exe, f91e4ff7811a5848561463d970c51870c9299a80117a89fb86a698b9f727de87.exe, 004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394"
      hash2 = "bc22a0e87e9ffae8c2aa04a35879be6f5fbef9da24897b9c00ea0fa28ae7a5f5"
      hash3 = "f91e4ff7811a5848561463d970c51870c9299a80117a89fb86a698b9f727de87"
      hash4 = "004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41"
   strings:
      $s1 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s2 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s3 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s4 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s5 = "http://ocsp.digicert.com0X" fullword ascii
      $s6 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii
      $s7 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii
      $s8 = "DigiCert Timestamp 2022 - 20" fullword ascii
      $s9 = "DigiCert1$0\"" fullword ascii
      $s10 = "v=Y]Bv" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "]J<0\"0i3" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "DigiCert Trusted Root G40" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "DigiCert, Inc.1;09" fullword ascii
      $s14 = "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA0" fullword ascii
      $s15 = "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA" fullword ascii
      $s16 = "370322235959" ascii
      $s17 = "331121235959" ascii
      $s18 = "311109235959" ascii
      $s19 = "370322235959Z0c1" fullword ascii
      $s20 = "311109235959Z0b1" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f_8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4_46 {
   meta:
      description = "samples - from files b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f.exe, 8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f"
      hash2 = "8e5b0faa4ec49043dea0ece20bcde74ab60cf0731aab80fc9189616bc4643943"
   strings:
      $s1 = "Repeat" fullword ascii /* Goodware String - occured 61 times */
      $s2 = "dictionary" fullword ascii /* Goodware String - occured 216 times */
      $s3 = "command" fullword ascii /* Goodware String - occured 524 times */
      $s4 = "source" fullword ascii /* Goodware String - occured 998 times */
      $s5 = "<>9__1_0" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( all of them )
      ) or ( all of them )
}

rule _a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072_004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00d_47 {
   meta:
      description = "samples - from files a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072.exe, 004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072"
      hash2 = "004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41"
   strings:
      $s1 = "(Symantec SHA256 TimeStamping Signer - G3" fullword ascii
      $s2 = "(Symantec SHA256 TimeStamping Signer - G30" fullword ascii
      $s3 = "TimeStamp-2048-60" fullword ascii
      $s4 = "310111235959" ascii
      $s5 = "290322235959" ascii
      $s6 = "290322235959Z0" fullword ascii
      $s7 = "?'J3Nm" fullword ascii
      $s8 = "U){9FN" fullword ascii
      $s9 = "171223000000Z" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _ebb35d31b8c44c163ecaadef47d7f6249cc1d2c654fa5afb1011ea1527fea927_9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d_48 {
   meta:
      description = "samples - from files ebb35d31b8c44c163ecaadef47d7f6249cc1d2c654fa5afb1011ea1527fea927.exe, 9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "ebb35d31b8c44c163ecaadef47d7f6249cc1d2c654fa5afb1011ea1527fea927"
      hash2 = "9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926"
   strings:
      $s1 = "lpdwProcessID" fullword ascii
      $s2 = "cbKeyObject" fullword ascii
      $s3 = "pbKeyObject" fullword ascii
      $s4 = "BCryptSetAlgorithmProperty" fullword ascii
      $s5 = "phAlgorithm" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "pszBlobType" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "wVirtKey" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "pcbResult" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "cchBuff" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "pbOutput" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "pPaddingInfo" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "pbInput" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "wScanCode" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "hImportKey" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "pszImplementation" fullword ascii /* Goodware String - occured 3 times */
      $s16 = " KDBM(*" fullword ascii
      $s17 = "lpKeyState" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214_fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf_49 {
   meta:
      description = "samples - from files 82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214.exe, fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553.exe, 215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214"
      hash2 = "fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553"
      hash3 = "215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498"
   strings:
      $s1 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
      $s2 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii
      $s3 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s4 = "             requestedExecutionLevel node with one of the following." fullword ascii
      $s5 = "        <requestedExecutionLevel  level=\"highestAvailable\" uiAccess=\"false\" />" fullword ascii
      $s6 = "       to opt in. Windows Forms applications targeting .NET Framework 4.6 that opt into this setting, should " fullword ascii
      $s7 = "            Specifying requestedExecutionLevel element will disable file and registry virtualization. " fullword ascii
      $s8 = "        <requestedExecutionLevel  level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii
      $s9 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" fullword ascii
      $s10 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" fullword ascii
      $s11 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" fullword ascii
      $s12 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" fullword ascii
      $s13 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" fullword ascii
      $s14 = "        -->" fullword ascii
      $s15 = "             If you want to change the Windows User Account Control level replace the " fullword ascii
      $s16 = "  <!-- Indicates that the application is DPI-aware and will not be automatically scaled by Windows at higher" fullword ascii
      $s17 = "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s18 = "        <!-- UAC Manifest Options" fullword ascii
      $s19 = "            compatibility." fullword ascii
      $s20 = "  <!--" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f_d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7f_50 {
   meta:
      description = "samples - from files b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f.exe, d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7fbc757d.exe, 9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926.exe, b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26.exe, a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a.exe, 96a6df07b7d331cd6fb9f97e7d3f2162e56f03b7f2b7cdad58193ac1d778e025.exe, 1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3.exe, f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f.exe, 215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f"
      hash2 = "d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7fbc757d"
      hash3 = "9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926"
      hash4 = "b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26"
      hash5 = "a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a"
      hash6 = "96a6df07b7d331cd6fb9f97e7d3f2162e56f03b7f2b7cdad58193ac1d778e025"
      hash7 = "1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3"
      hash8 = "f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f"
      hash9 = "215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498"
   strings:
      $s1 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
      $s2 = "My.Computer" fullword ascii
      $s3 = "MyTemplate" fullword ascii
      $s4 = "System.Windows.Forms.Form" fullword ascii
      $s5 = "My.WebServices" fullword ascii
      $s6 = "GetResourceString" fullword ascii /* Goodware String - occured 124 times */
      $s7 = "Create__Instance__" fullword ascii
      $s8 = "My.User" fullword ascii
      $s9 = "My.MyProject.Forms" fullword ascii
      $s10 = "Dispose__Instance__" fullword ascii
      $s11 = "My.Forms" fullword ascii
      $s12 = "My.Application" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a_974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e75_51 {
   meta:
      description = "samples - from files 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe, 582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash2 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
      hash3 = "582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f"
      hash4 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "fotod250" fullword ascii
      $s2 = "oWFcMuL" fullword ascii
      $s3 = "tWQ\"^W" fullword ascii
      $s4 = "H/(->f(" fullword ascii
      $s5 = "oN-P:2" fullword ascii
      $s6 = "KmC`5L " fullword ascii
      $s7 = "Yjr:E$&]" fullword ascii
      $s8 = "C05)[\"C" fullword ascii
      $s9 = "nIq/,." fullword ascii
      $s10 = "&b~zhc" fullword ascii
      $s11 = "Jo(6Ri$" fullword ascii
      $s12 = "0^<^`^" fullword ascii
      $s13 = "V/]/ZZ]" fullword ascii
      $s14 = "AtD% v" fullword ascii
      $s15 = "62l(1rF9" fullword ascii
      $s16 = "\"I$0Qa" fullword ascii
      $s17 = "Q/2G$~" fullword ascii
      $s18 = "YJH_T-" fullword ascii
      $s19 = "S6gjy3" fullword ascii
      $s20 = "J&0I42" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14_df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d_52 {
   meta:
      description = "samples - from files 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash2 = "df4f2bd477daed3aa0c4665f2b989157fa971af504981ebd35c4af660d82ccb1"
   strings:
      $s1 = "V%FP{ms" fullword ascii
      $s2 = "?JvPVH" fullword ascii
      $s3 = "s[q YK" fullword ascii
      $s4 = "o&4g%)" fullword ascii
      $s5 = "\"<7:`~WFF" fullword ascii
      $s6 = "D)1ezT" fullword ascii
      $s7 = "#^1P2(q" fullword ascii
      $s8 = "zA,.<g" fullword ascii
      $s9 = "fH'IKi" fullword ascii
      $s10 = "@GM>DGNK" fullword ascii
      $s11 = "HUm++J" fullword ascii
      $s12 = "+=<y,f" fullword ascii
      $s13 = "=9PaD7D$)u" fullword ascii
      $s14 = "g-cU)Z" fullword ascii
      $s15 = "c7[G]." fullword ascii
      $s16 = "P0t:o[$" fullword ascii
      $s17 = "-2_R%sl" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394_327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a3_53 {
   meta:
      description = "samples - from files 7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394.exe, 327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba.exe, 23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b.exe, 6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394"
      hash2 = "327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba"
      hash3 = "23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b"
      hash4 = "6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599"
   strings:
      $s1 = "u,PQRS" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "u2Vj@h" fullword ascii
      $s3 = "SWt@jU" fullword ascii
      $s4 = "V2jx_f;" fullword ascii
      $s5 = "Jjl^f;" fullword ascii
      $s6 = "jg[BjG_" fullword ascii
      $s7 = "NX9^`t1" fullword ascii
      $s8 = "ARPRQh" fullword ascii
      $s9 = ";V\\uYW" fullword ascii
      $s10 = "9C`u99C\\t4" fullword ascii
      $s11 = "_tqPVj@" fullword ascii
      $s12 = "7;1u\"3" fullword ascii
      $s13 = "u29K\\t-" fullword ascii
      $s14 = "x!j$Xf9" fullword ascii
      $s15 = "tlj*Yf" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3_54 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "/'/nzv" fullword ascii
      $s2 = "YtwU_V" fullword ascii
      $s3 = "zuH5!z" fullword ascii
      $s4 = "!z)%M]j{" fullword ascii
      $s5 = "byY|cf" fullword ascii
      $s6 = "`]:HT:" fullword ascii
      $s7 = "gmQlqG" fullword ascii
      $s8 = "`.o~~M[" fullword ascii
      $s9 = "q!=C.Ez" fullword ascii
      $s10 = "5TIcSK" fullword ascii
      $s11 = "Z9+Q8G" fullword ascii
      $s12 = ";}:eT59R" fullword ascii
      $s13 = "SI-\\QK" fullword ascii
      $s14 = "c30s%'2" fullword ascii
      $s15 = "#e::2O" fullword ascii
      $s16 = "<<j\"6TL" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74_f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1_55 {
   meta:
      description = "samples - from files b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74.exe, f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400.exe, 7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74"
      hash2 = "f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400"
      hash3 = "7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1"
   strings:
      $s1 = "\"K KBCd" fullword ascii
      $s2 = "?? Hy%" fullword ascii
      $s3 = "3U!hE3" fullword ascii
      $s4 = "FV vDR!" fullword ascii
      $s5 = "jZ:c5(" fullword ascii
      $s6 = "[[]EN>" fullword ascii
      $s7 = "+&m]B@" fullword ascii
      $s8 = "pL2r4&l" fullword ascii
      $s9 = "C`NFgN" fullword ascii
      $s10 = "`5:d}2" fullword ascii
      $s11 = "<~;o|O" fullword ascii
      $s12 = "L7T+o&" fullword ascii
      $s13 = "mK[.`y" fullword ascii
      $s14 = "ucq30&)W" fullword ascii
      $s15 = "O`~a=:9" fullword ascii
      $s16 = "<KDE2;" fullword ascii
      $s17 = "n:1U1]" fullword ascii
      $s18 = "JO`QSp#m2pz" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d8_56 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash3 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
      hash4 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
   strings:
      $s1 = "6uIei " fullword ascii
      $s2 = "ytGKf~" fullword ascii
      $s3 = "#O Y>2S" fullword ascii
      $s4 = "&:F<YQ" fullword ascii
      $s5 = "lR)N3V" fullword ascii
      $s6 = "l'pG_G" fullword ascii
      $s7 = "sg_FF?" fullword ascii
      $s8 = "NOW+^+l*w" fullword ascii
      $s9 = "a7b7sn" fullword ascii
      $s10 = "/nK_Gc" fullword ascii
      $s11 = "/{CV+M" fullword ascii
      $s12 = "/f/Q\\Z" fullword ascii
      $s13 = "@&j 0`" fullword ascii
      $s14 = "Lq4fqq" fullword ascii
      $s15 = "GHjAtC" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1e_57 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
   strings:
      $s1 = ".CRm|g" fullword ascii
      $s2 = "AvAB8e'" fullword ascii
      $s3 = "WGrX?)" fullword ascii
      $s4 = "xmn%qW" fullword ascii
      $s5 = "KL\"NFH" fullword ascii
      $s6 = "_(82W(" fullword ascii
      $s7 = ".i/&RS" fullword ascii
      $s8 = "rf6o<YG" fullword ascii
      $s9 = "~|_1 `" fullword ascii
      $s10 = "7`W*D@`" fullword ascii
      $s11 = "(_*tv4/" fullword ascii
      $s12 = "<t9U/<" fullword ascii
      $s13 = "3>732=!2}" fullword ascii
      $s14 = "~j'2km" fullword ascii
      $s15 = "x';vj;" fullword ascii
      $s16 = "#rp){\"+" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74_dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce1_58 {
   meta:
      description = "samples - from files b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74.exe, dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74"
      hash2 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
   strings:
      $s1 = "\\E&yL Y" fullword ascii
      $s2 = "xJne%v" fullword ascii
      $s3 = "0?fHb>" fullword ascii
      $s4 = "DB8w4\"" fullword ascii
      $s5 = "/hrPY`" fullword ascii
      $s6 = "wZ`?>31" fullword ascii
      $s7 = "u(ZPT6ZU" fullword ascii
      $s8 = "FeJ,7_" fullword ascii
      $s9 = "V'Szpc" fullword ascii
      $s10 = "-`$Ne[^" fullword ascii
      $s11 = "@.}**w" fullword ascii
      $s12 = "S-glt=" fullword ascii
      $s13 = "H:<Dva" fullword ascii
      $s14 = "fP+}#6" fullword ascii
      $s15 = "w7h+|X" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _f91e4ff7811a5848561463d970c51870c9299a80117a89fb86a698b9f727de87_004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00d_59 {
   meta:
      description = "samples - from files f91e4ff7811a5848561463d970c51870c9299a80117a89fb86a698b9f727de87.exe, 004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "f91e4ff7811a5848561463d970c51870c9299a80117a89fb86a698b9f727de87"
      hash2 = "004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii
      $s2 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii
      $s3 = "http://ocsp.digicert.com0\\" fullword ascii
      $s4 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii
      $s5 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0>" fullword ascii
      $s6 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii
      $s7 = "DigiCert, Inc.1A0?" fullword ascii
      $s8 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA10" fullword ascii
      $s9 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" fullword ascii
      $s10 = "360428235959" ascii
      $s11 = "jj@0HK4" fullword ascii
      $s12 = "210429000000Z" fullword ascii
      $s13 = "SA|X=G" fullword ascii
      $s14 = "[K]taM?" fullword ascii
      $s15 = "360428235959Z0i1" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14_018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3_60 {
   meta:
      description = "samples - from files 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash2 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "0,La08" fullword ascii
      $s2 = "7$eN\\<" fullword ascii
      $s3 = "O#\\4k~" fullword ascii
      $s4 = "dNk_WO" fullword ascii
      $s5 = "Usa!Th" fullword ascii
      $s6 = "iy0m.>Q" fullword ascii
      $s7 = "3it><K" fullword ascii
      $s8 = "lo^}I)O" fullword ascii
      $s9 = "[6 {ns@356." fullword ascii
      $s10 = "Xuu'svv" fullword ascii
      $s11 = "K>fEga" fullword ascii
      $s12 = "Es8;i?!" fullword ascii
      $s13 = "9vft)O" fullword ascii
      $s14 = "}63wSC" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a_f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6_61 {
   meta:
      description = "samples - from files 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash2 = "f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48"
   strings:
      $s1 = "NGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s2 = "PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDI" ascii /* Goodware String - occured 1 times */
      $s3 = "#RVpx!" fullword ascii
      $s4 = "Ar!)dw" fullword ascii
      $s5 = "*b\\;uU" fullword ascii
      $s6 = "1Gg'cu'" fullword ascii
      $s7 = "Ygu/$&" fullword ascii
      $s8 = "5hXPc==" fullword ascii
      $s9 = "yZ4 jy" fullword ascii
      $s10 = "m3(u\"Xr" fullword ascii
      $s11 = "r*)y%q" fullword ascii
      $s12 = "f*$D+)v2" fullword ascii
      $s13 = "93Fl\\:*" fullword ascii
      $s14 = "d,r\\DK" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e75_62 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
   strings:
      $s1 = "},h6-O" fullword ascii
      $s2 = "=/\\id4X" fullword ascii
      $s3 = ")J@XHY" fullword ascii
      $s4 = "?RC d7" fullword ascii
      $s5 = "J072e5{" fullword ascii
      $s6 = "`W hkt" fullword ascii
      $s7 = "3vw8Tn" fullword ascii
      $s8 = "i&8jY]$3" fullword ascii
      $s9 = ":N*]Vyt" fullword ascii
      $s10 = "8o$bgL>" fullword ascii
      $s11 = "&B}ky5%|xo" fullword ascii
      $s12 = "KXAhWE4" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d_63 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
   strings:
      $s1 = "#PWkQVII" fullword ascii
      $s2 = "UWIbQ*m" fullword ascii
      $s3 = "hISw/*d>" fullword ascii
      $s4 = "lcR')B" fullword ascii
      $s5 = ";iT|\\S" fullword ascii
      $s6 = "ntL`1A!" fullword ascii
      $s7 = "{7'Gz=" fullword ascii
      $s8 = "Jb~-`[" fullword ascii
      $s9 = "BR^%R4" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74_582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb6_64 {
   meta:
      description = "samples - from files b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74.exe, 582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74"
      hash2 = "582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f"
   strings:
      $s1 = "vzoi\"]" fullword ascii
      $s2 = "%^o+[k" fullword ascii
      $s3 = "kyyjL." fullword ascii
      $s4 = "kFY-WF" fullword ascii
      $s5 = "Ly`n\\4N{" fullword ascii
      $s6 = "x|N<$e" fullword ascii
      $s7 = "c?o3h^" fullword ascii
      $s8 = "2!!&w " fullword ascii
      $s9 = "_lwqVX" fullword ascii
      $s10 = "5M1BRB" fullword ascii
      $s11 = "`MQ9EGC" fullword ascii
      $s12 = "wspPg@>!&i" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc_882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d_65 {
   meta:
      description = "samples - from files 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
      hash2 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
   strings:
      $s1 = "nj==(>" fullword ascii
      $s2 = "f?9M+M" fullword ascii
      $s3 = "4{x{S&" fullword ascii
      $s4 = "'Kc9q&\"" fullword ascii
      $s5 = "R>sMM?)" fullword ascii
      $s6 = "2ws5wz{" fullword ascii
      $s7 = "mh6fjX" fullword ascii
      $s8 = "`PVLQ|" fullword ascii
      $s9 = "l Fm08R2'jR" fullword ascii
      $s10 = "Z6IR+:" fullword ascii
      $s11 = "$(=\\}K" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394_9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efc_66 {
   meta:
      description = "samples - from files 7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394.exe, 9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252.exe, 327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba.exe, 0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc.exe, 2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2.exe, 2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6.exe, 23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b.exe, 6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599.exe, 8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394"
      hash2 = "9abd2d92775e67d961f0d0ac7d776e3440f4bf68fea532d35c2b746efccb7252"
      hash3 = "327fdd0215c36138e9865fff7ffdd8269a02e70dee9b1942cde57fe0a38d36ba"
      hash4 = "0e41ffd44bc8a085a3bd49058ff0051538476c8a05f086593b02bc87b30268dc"
      hash5 = "2c31b03c00592c9938b625c4f2cb659932bd1684e766d73bb2f7a34a11bb93c2"
      hash6 = "2a3c0d7e6bddf093b92e649c51fff89df7588e835b4d16a1fd15508210b2e9c6"
      hash7 = "23e3579264426af8e34718043ab5f2ebae5ca638c459ce74276d2a097191079b"
      hash8 = "6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599"
      hash9 = "8deda3f9f857a91d1d9b3f420a3d9102a091849696a8f34b91e9413fc954a82f"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "operator<=>" fullword ascii
      $s3 = "operator co_await" fullword ascii
      $s4 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s5 = "__swift_1" fullword ascii
      $s6 = "__swift_2" fullword ascii
      $s7 = "api-ms-" fullword wide
      $s8 = "ext-ms-" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( all of them )
      ) or ( all of them )
}

rule _82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214_fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf_67 {
   meta:
      description = "samples - from files 82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214.exe, fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214"
      hash2 = "fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553"
   strings:
      $s1 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii
      $s2 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii
      $s3 = "      <longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii
      $s4 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\" />" fullword ascii
      $s5 = "           and Windows will automatically select the most compatible environment. -->" fullword ascii
      $s6 = "      <!-- A list of the Windows versions that this application has been tested on" fullword ascii
      $s7 = "       also set the 'EnableWindowsFormsHighDpiAutoResizing' setting to 'true' in their app.config. " fullword ascii
      $s8 = "           and is designed to work with. Uncomment the appropriate elements" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc_582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb6_68 {
   meta:
      description = "samples - from files 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe, 582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
      hash2 = "582757293348d382046505c2bac4cdd2e2adc48442e9d25f8740438fb652aa7f"
   strings:
      $s1 = "zDze\\i" fullword ascii
      $s2 = "0z]^13a" fullword ascii
      $s3 = "=u-0\\d" fullword ascii
      $s4 = "|=}5]P" fullword ascii
      $s5 = "TfKF:v" fullword ascii
      $s6 = "-_Yw~#P" fullword ascii
      $s7 = "X'pGlL" fullword ascii
      $s8 = ">N[565" fullword ascii
      $s9 = "|bQ Ux" fullword ascii
      $s10 = "g0Qg4<" fullword ascii
      $s11 = "F!k_s*" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26_a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d8_69 {
   meta:
      description = "samples - from files b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26.exe, a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a.exe, 1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3.exe, f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26"
      hash2 = "a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a"
      hash3 = "1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3"
      hash4 = "f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f"
   strings:
      $s1 = "addedHandler" fullword ascii
      $s2 = "Button1_Click" fullword ascii
      $s3 = "addedHandlerLockObject" fullword ascii
      $s4 = "AutoSaveSettings" fullword ascii
      $s5 = "set_Button1" fullword ascii
      $s6 = "get_Button1" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f_004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00d_70 {
   meta:
      description = "samples - from files b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f.exe, 004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b3e6df655099d01cb24029b5d7f4a56da32caf9144c01672537c17f7497dcd2f"
      hash2 = "004ad4b8d03c06098e99e6ad78e188832d40548e9cf9d9e54a2723f00dcdce41"
   strings:
      $s1 = "<>9__35_0" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "<>9__22_1" fullword ascii
      $s3 = "<>9__22_2" fullword ascii
      $s4 = "<>9__22_0" fullword ascii
      $s5 = "<>9__18_0" fullword ascii
      $s6 = "<>9__5_0" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and ( all of them )
      ) or ( all of them )
}

rule _fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af_17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd0_71 {
   meta:
      description = "samples - from files fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af.exe, 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af"
      hash2 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash3 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
      hash4 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
   strings:
      $s1 = "RwZX(2#" fullword ascii
      $s2 = "eZs`%\"%" fullword ascii
      $s3 = "HsBA:>" fullword ascii
      $s4 = "[nZ+|A]" fullword ascii
      $s5 = "~6v)jd5" fullword ascii
      $s6 = "TS5[\\2" fullword ascii
      $s7 = "P/1D~C" fullword ascii
      $s8 = "tg|[Dh" fullword ascii
      $s9 = "m9SqjW" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14_882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d_72 {
   meta:
      description = "samples - from files 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash2 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
   strings:
      $s1 = "=!*ZO." fullword ascii
      $s2 = "[;#E+-" fullword ascii
      $s3 = "ww}wON" fullword ascii
      $s4 = "!g{FWn/" fullword ascii
      $s5 = "5&uuqm" fullword ascii
      $s6 = "8`(vf7" fullword ascii
      $s7 = "eJMoWQ" fullword ascii
      $s8 = "-Z,Bb\\b" fullword ascii
      $s9 = "/ Qcb8" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394_6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bc_73 {
   meta:
      description = "samples - from files 7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394.exe, 6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "7e93fa1eab66dd0436c705a8d5163e850d6e0a67374ca7aefb4c3cafd8145394"
      hash2 = "6d844db8d4cf6048f06a11dafe55c3f02d71c9a4bb236b56f912dfb9bcfa4599"
   strings:
      $s1 = "5 5D5L5T5\\5h5" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "7(747X7d7" fullword ascii /* Goodware String - occured 2 times */
      $s3 = "3$3,343<3T3\\3h3" fullword ascii
      $s4 = "6 6,6T6`6" fullword ascii
      $s5 = "2@2L2p2|2" fullword ascii
      $s6 = "1,141@1h1p1|1" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a521_74 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74"
   strings:
      $s1 = "?WE@,cW" fullword ascii
      $s2 = "p=QxG_ " fullword ascii
      $s3 = "{-HE!S" fullword ascii
      $s4 = "Z]M(OV" fullword ascii
      $s5 = "??37x7" fullword ascii
      $s6 = "Qk8c>dq" fullword ascii
      $s7 = "8N4;0I" fullword ascii
      $s8 = "w?<&cP" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a_dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce1_75 {
   meta:
      description = "samples - from files 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash2 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
   strings:
      $s1 = "yu|/HD" fullword ascii
      $s2 = ";,%6=S" fullword ascii
      $s3 = "oE\\52SGaX|v" fullword ascii
      $s4 = "pf1m>H" fullword ascii
      $s5 = "-W|S%Y" fullword ascii
      $s6 = "/s8_Yq." fullword ascii
      $s7 = "Q9]!#]hB6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14_5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d_76 {
   meta:
      description = "samples - from files 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash2 = "5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5"
   strings:
      $s1 = "~M6[(3" fullword ascii
      $s2 = "+Mvk#\"" fullword ascii
      $s3 = "?eg@IS" fullword ascii
      $s4 = "<ef:?sm" fullword ascii
      $s5 = "q.'Hsw" fullword ascii
      $s6 = "i%,<:l" fullword ascii
      $s7 = "|K7Vz+/Q" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5_f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6_77 {
   meta:
      description = "samples - from files 5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5.exe, f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5"
      hash2 = "f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48"
   strings:
      $s1 = "eYE;F`^8" fullword ascii
      $s2 = "tYMp({1" fullword ascii
      $s3 = "K)(s:j" fullword ascii
      $s4 = "._@wjU" fullword ascii
      $s5 = "@\"\"h7u7" fullword ascii
      $s6 = "V[\\>;]" fullword ascii
      $s7 = "nu\\J1Z4J" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e_c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9_78 {
   meta:
      description = "samples - from files 09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e.exe, c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19.exe, 46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2.exe, 149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443.exe, 258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec.exe, 02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241.exe, 3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93.exe, b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193.exe, 0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e.exe, a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e"
      hash2 = "c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19"
      hash3 = "46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2"
      hash4 = "149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443"
      hash5 = "258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec"
      hash6 = "02a054c8e4659ad41a302225d7a9ab51ef04be66c2f9a52ae6bacaa2ff2d2241"
      hash7 = "3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93"
      hash8 = "b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193"
      hash9 = "0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e"
      hash10 = "a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a"
   strings:
      $s1 = "D$0VSP" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "T$$RPPf" fullword ascii
      $s3 = "t$@9l$Ds" fullword ascii
      $s4 = "F\\=X!@" fullword ascii
      $s5 = "D$(PWWW" fullword ascii /* Goodware String - occured 4 times */
      $s6 = "D$dPQQ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e_c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9_79 {
   meta:
      description = "samples - from files 09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e.exe, c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19.exe, 46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2.exe, 149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443.exe, 258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec.exe, 3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93.exe, b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193.exe, 0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e.exe, a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "09fefc1bda70f0a2802550557ccb84398449523bcada5d4fbcc4a2114fda2f5e"
      hash2 = "c9d61842904c94a0a518478b2e9a81814b1bac45579d077bb4d5e628a9556d19"
      hash3 = "46441de670dd242c79189adc4e679762941a7cda44f68931005f693828d221e2"
      hash4 = "149bee1495ab2af3c3eb23f2e84bc7f82539abd216bf3109f1356fc529e18443"
      hash5 = "258dc9e5507e00b29d505ea26b2337d15a18fc7b0e9271ba18804ade7f9069ec"
      hash6 = "3ba8dee660c59344195a30c210088161d2a0c05dd6c9b231c1c722c7f6b0ce93"
      hash7 = "b171ce1f152c422dad695f8570c9355fb5726201ef4c23057e26bc72f19c0193"
      hash8 = "0aeabd2cce82133225f93a32f88d3a1ac58b149f1b897d7467fcfbd02369330e"
      hash9 = "a752658b48b4c8f755059d9cd2af82cc761a4e157bb4c774773089311294f57a"
   strings:
      $s1 = "BigWind.exe" fullword wide
      $s2 = "topuhiwaliwobobiyisijewofafineva josicexaxecifiheciwafuzove naloxuraceyeru" fullword ascii
      $s3 = "nERichK" fullword ascii
      $s4 = "D$hd4@" fullword ascii
      $s5 = "u-h|5@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}

rule _b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26_1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965a_80 {
   meta:
      description = "samples - from files b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26.exe, 1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3.exe, f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26"
      hash2 = "1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3"
      hash3 = "f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f"
   strings:
      $s1 = "set_Button3" fullword ascii
      $s2 = "Button2_Click" fullword ascii
      $s3 = "Button3_Click" fullword ascii
      $s4 = "set_Button2" fullword ascii
      $s5 = "Poor Richard" fullword wide
      $s6 = "get_Button3" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "get_Button2" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d8_81 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash3 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
   strings:
      $s1 = "e>U5?-" fullword ascii
      $s2 = "tQ0j2I" fullword ascii
      $s3 = "piA6F{" fullword ascii
      $s4 = "QjXVa]" fullword ascii
      $s5 = "$Vwxhd" fullword ascii
      $s6 = "97yd`6" fullword ascii
      $s7 = "J?c'<K" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a_60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d8_82 {
   meta:
      description = "samples - from files 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash2 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash3 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
      hash4 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
      hash5 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "1eaaT5_sRB" fullword ascii
      $s2 = "k(}%Ct" fullword ascii
      $s3 = "5w|Ks2|" fullword ascii
      $s4 = ">GD*-h" fullword ascii
      $s5 = "40>r1X" fullword ascii
      $s6 = "L4Pt{0=" fullword ascii
      $s7 = "[27lZo" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc_018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3_83 {
   meta:
      description = "samples - from files 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
      hash2 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "^Y.GBs" fullword ascii
      $s2 = "3,(pZ'" fullword ascii
      $s3 = "@>W})li" fullword ascii
      $s4 = "(1P!}Tbq" fullword ascii
      $s5 = "6oR.(-" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5_882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d_84 {
   meta:
      description = "samples - from files 5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5.exe, 882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5"
      hash2 = "882fbe014ccbfa350eb3a7d1b61f5ecba4fa5379ac293dfcb4541df72d8d97ff"
   strings:
      $s1 = "\\SYM).?" fullword ascii
      $s2 = "cUbM#G" fullword ascii
      $s3 = "++U>mm" fullword ascii
      $s4 = "i\").`EI" fullword ascii
      $s5 = "g4s45dz" fullword ascii
      $s6 = "ZSZ'v<'" fullword ascii
      $s7 = "+{M8` " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072_566dba1fe1103869980a78a3e18e3d62e2be44935a27c825024f94fe56_85 {
   meta:
      description = "samples - from files a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072.exe, 566dba1fe1103869980a78a3e18e3d62e2be44935a27c825024f94fe56d7be7b.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "a23baf6242f0bb5b11356a4a1edd873856b3839658e0fe2e7d97464b0dd42072"
      hash2 = "566dba1fe1103869980a78a3e18e3d62e2be44935a27c825024f94fe56d7be7b"
   strings:
      $s1 = "ecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:sch" ascii
      $s2 = "6-80e1-4239-95bb-83d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4" ascii
      $s3 = "NTMARTA" fullword ascii
      $s4 = "microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f6" ascii
      $s5 = "NullsoftInst" fullword ascii /* Goodware String - occured 89 times */
      $s6 = "8e2d-a2440225f93a}\"/></application></compatibility></assembly>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd0_86 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash3 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
   strings:
      $s1 = "jRd;KuG" fullword ascii
      $s2 = "[+GW,X" fullword ascii
      $s3 = "/W0Di%Nt" fullword ascii
      $s4 = "eG}jpv<I" fullword ascii
      $s5 = "o+GCJ$" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e_17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd0_87 {
   meta:
      description = "samples - from files 14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e.exe, 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "14703def02b8604e852ae658ef894cd7e2b3cdcd670172e3f4a9d591362c686e"
      hash2 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash3 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
   strings:
      $s1 = "D43!\\w" fullword ascii
      $s2 = "2C7E,A!" fullword ascii
      $s3 = "WW7yaQ3" fullword ascii
      $s4 = "f8gHk*" fullword ascii
      $s5 = "BA-B.6" fullword ascii
      $s6 = "-P3,Zy" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af_dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce1_88 {
   meta:
      description = "samples - from files fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af.exe, dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af"
      hash2 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
   strings:
      $s1 = "tj/mdw;e" fullword ascii
      $s2 = "'Mv`'E~" fullword ascii
      $s3 = "`ZBJ/d" fullword ascii
      $s4 = "e!mV-5U" fullword ascii
      $s5 = "( W=yy'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a_60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d8_89 {
   meta:
      description = "samples - from files 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash2 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
   strings:
      $s1 = "&D$*&X" fullword ascii
      $s2 = "#t#<-D" fullword ascii
      $s3 = "*A75(A?" fullword ascii
      $s4 = ")sfm_y" fullword ascii
      $s5 = "57@-L{" fullword ascii
      $s6 = "+=uQ3:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14_7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c6332842_90 {
   meta:
      description = "samples - from files 60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14.exe, 7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "60a027d5534ff79eb66c3f22690de46994a78237d529745c20dafd20d86eae14"
      hash2 = "7350bc78f411455f292cba6d010ade5e8e4734c0c251b76238c63328420b49b1"
   strings:
      $s1 = "kVK[G_" fullword ascii
      $s2 = "*iAw![" fullword ascii
      $s3 = " OJW>\\" fullword ascii
      $s4 = "@EhcM^" fullword ascii
      $s5 = "rdq4YmL" fullword ascii
      $s6 = "8eWy-`" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc_5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d_91 {
   meta:
      description = "samples - from files 974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc.exe, 5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "974dfd9ffeada2bfe533ea32f4021ea271b6ca731d5fd737f763230e750c16dc"
      hash2 = "5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5"
   strings:
      $s1 = "X<damc" fullword ascii
      $s2 = "*HDEI6" fullword ascii
      $s3 = "Uh1uZ=" fullword ascii
      $s4 = "#&f|-0" fullword ascii
      $s5 = "B9kl6eT" fullword ascii
      $s6 = "y$#[<#" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7fbc757d_9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d_92 {
   meta:
      description = "samples - from files d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7fbc757d.exe, 9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926.exe, b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26.exe, a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a.exe, 96a6df07b7d331cd6fb9f97e7d3f2162e56f03b7f2b7cdad58193ac1d778e025.exe, 1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3.exe, f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "d75142e16f20c436796b90c42e46afc3d25bb4003c60a264e437643b7fbc757d"
      hash2 = "9d96a7f4d13ee5d4fe74dace7787d6573111eb1104239f2cfbca79810d309926"
      hash3 = "b86b07dd168ae86bbfc16822df78793e8fbf52401673636047e8472fcd78ff26"
      hash4 = "a5d9266bd64b0bb3fc1fa6fe9da781141bc7867d6381601056823cb2d80a655a"
      hash5 = "96a6df07b7d331cd6fb9f97e7d3f2162e56f03b7f2b7cdad58193ac1d778e025"
      hash6 = "1dbd4c8bfc62f2efc6bf56ad3847719fa0f42a29df856a388734e2965aeecaa3"
      hash7 = "f287b0d3ec6e6d8cadc14c4a50099d8632062a8b0765f9c9975e9452acff5b7f"
   strings:
      $s1 = "m_MyWebServicesObjectProvider" fullword ascii
      $s2 = "m_ComputerObjectProvider" fullword ascii
      $s3 = "m_UserObjectProvider" fullword ascii
      $s4 = "m_MyFormsObjectProvider" fullword ascii
      $s5 = "m_AppObjectProvider" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( all of them )
      ) or ( all of them )
}

rule _82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214_8811dde82b3c3bc28fba1619b7332ea654cb61f103f04e220e79402aa7_93 {
   meta:
      description = "samples - from files 82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214.exe, 8811dde82b3c3bc28fba1619b7332ea654cb61f103f04e220e79402aa711ac37.exe, fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553.exe, 215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "82173e481da69e58688c5221a5ff8e260fd50f0bbb0e2064def8620dcd0d5214"
      hash2 = "8811dde82b3c3bc28fba1619b7332ea654cb61f103f04e220e79402aa711ac37"
      hash3 = "fb553e12381d42a612c713968078424201794a35fd13c681ae7faa77bf18e553"
      hash4 = "215702bf56028f01483674d83da445ebd01c1c7dcdee7e4995a5c2f4cc25f498"
   strings:
      $s1 = "      <!-- Windows 8 -->" fullword ascii
      $s2 = "      <!-- Windows 8.1 -->" fullword ascii
      $s3 = "      <!-- Windows Vista -->" fullword ascii
      $s4 = "      <!-- Windows 7 -->" fullword ascii
      $s5 = "      <!-- Windows 10 -->" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( all of them )
      ) or ( all of them )
}

rule _b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74_f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1_94 {
   meta:
      description = "samples - from files b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74.exe, f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "b8ca9bbad9e702df33c91862a9d46739ddd81d9b1fdb391526a795a52121eb74"
      hash2 = "f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400"
   strings:
      $s1 = "+k]pnS&" fullword ascii
      $s2 = "R77>y8f" fullword ascii
      $s3 = "'LH~!D" fullword ascii
      $s4 = "*^ILTd" fullword ascii
      $s5 = "O?/,up" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af_17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd0_95 {
   meta:
      description = "samples - from files fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af.exe, 17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a.exe, 5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5.exe, dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe, f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "fc571f9a066e3ac0244f7cf1f5a8e67eaedb3a2cd88b19ed68309285962ad7af"
      hash2 = "17916644ce4dcf5ff237294a4ab966d1cb2c9b3a9f3dcf80a219f5bfd09bb12a"
      hash3 = "5bca134c015749974f2439de72d6a187da4235781e97e3654ac649102d5ee9a5"
      hash4 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
      hash5 = "f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48"
   strings:
      $s1 = "urzfmZ3i8" fullword ascii
      $s2 = "aK.@5n](" fullword ascii
      $s3 = "&qHv>Hq" fullword ascii
      $s4 = "SD#ZHx" fullword ascii
      $s5 = "K>[#0lB<" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400_bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1e_96 {
   meta:
      description = "samples - from files f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400.exe, bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "f5f214044dd10db805029bf7c248864c1aa83f53448e86e62e327170b1818400"
      hash2 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
   strings:
      $s1 = "NI*R.UdW" fullword ascii
      $s2 = "+Val-!" fullword ascii
      $s3 = ":O7Sf=&l" fullword ascii
      $s4 = ":J]Ytd" fullword ascii
      $s5 = "a(+2V<5K" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f_f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6_97 {
   meta:
      description = "samples - from files dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe, f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
      hash2 = "f8c5fbf4978f266cc010869c69bbc4f59d58405667d5c48cacecabfda6d97f48"
   strings:
      $s1 = "\\s_k`f" fullword ascii
      $s2 = "~Y#[Lyw" fullword ascii
      $s3 = "W kw~)m" fullword ascii
      $s4 = "BA.B2:" fullword ascii
      $s5 = "KmXzEB" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f_018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3_98 {
   meta:
      description = "samples - from files dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "dada7b2174eb90b0558c5b2e2541f9b1e6a751f36a00984795ac2e8ce11f8c8f"
      hash2 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "CSiEkoc" fullword ascii
      $s2 = "4<!Dw3" fullword ascii
      $s3 = "H\\@EW:XW" fullword ascii
      $s4 = "@O=y2CK" fullword ascii
      $s5 = "?O},iii" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0_018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3_99 {
   meta:
      description = "samples - from files bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0.exe, 018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f.exe"
      author = "Grim"
      reference = "@grimbinary"
      date = "2023-08-06"
      hash1 = "bf57c0d97d0d03401b33866bf5d6a8c0f1a110938d68dafb9ee8fc5c1eb91ce0"
      hash2 = "018fdbba29b99d3c772e93147ee6b47ace4b2f5de0767f4ead438accc3f41d8f"
   strings:
      $s1 = "sPDM>h" fullword ascii
      $s2 = "}aeMy$" fullword ascii
      $s3 = "})zR\\F" fullword ascii
      $s4 = "qdi{$/" fullword ascii
      $s5 = "C u;?." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

