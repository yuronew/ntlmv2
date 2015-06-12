' ===========================================================
' Copyright (c) 2012, Marcel Schoen, Switzerland
' This script is available under the LGPL license as part of
' the "ntlmv2-auth" project:
'
' https://sourceforge.net/p/ntlmv2auth/wiki/Home/
' 
' Usage:
' 
' C:> cscript SetComputerAccountPassword.vbs <account DN>
' 
' ===========================================================
'
Option Explicit

Dim strDn, objPassword, strPassword, objComputer

If WScript.arguments.count <> 1 Then
	WScript.Echo "Usage: cscript SetComputerAccountPassword.vbs <ComputerDN>"
	WScript.Quit
End If

' Get the DN from the first commandline argument
strDn = WScript.arguments.item(0)

WScript.Echo "Please enter new password:"
Set objPassword = CreateObject("ScriptPW.Password")
strPassword = objPassword.GetPassword()

' Get the computer account object and set the new password for it
Set objComputer = GetObject("LDAP://" & strDn)
objComputer.SetPassword strPassword

WScript.Echo "Password successfully changed."
WScript.Quit
