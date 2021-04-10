---
layout: post
toc: true
title: "Exploiting Windows RPC to bypass CFG mitigation: analysis of CVE-2021-26411 in-the-wild sample"
tags: [exploit, itw, ie]
author:
  - iamelli0t
---

The general method of browser render process exploit is: after exploiting the vulnerability to obtain user mode arbitrary memory read/write primitive, the vtable of DOM/js object is tampered to hijack the code execution flow. Then VirtualProtect is called by ROP chain to modify the shellcode memory to PAGE_EXECUTE_READWRITE, and the code execution flow is jumped to shellcode by ROP chain finally. After Windows 8.1, Microsoft introduced CFG (Control Flow Guard)[1] mitigation to verify the indirect function call, which mitigates the exploitation of tampering with vtable.<br>

However, the confrontation is not end. Some new methods to bypass CFG mitigation  have emerged. For example, in chakra/jscript9, the code execution flow is hijacked by tampering with the function return address on the stack; in v8, WebAssembly with executable memory property is used to executes shellcode. In December 2020, Microsoft introduced CET[2] mitigation technology based on Intel Tiger Lake CPU in Windows 10 20H1, which protects the exploitation of tampering with the function return address on the stack. Therefore, how to bypass CFG in a CET mitigation environment has become a new problem for vulnerability exploitation.<br>

When analyzing CVE-2021-26411 the in-the-wild sample, we found a new method to bypass CFG mitigation using Windows RPC (Remote Procedure Call)[3]. This method does not rely on the ROP chain. By constructing RPC_MESSAGE, arbitrary code execution can be achieved by calling rpcrt4!NdrServerCall2 manually. <br>

##  CVE-2021-26411 Retrospect
My blog of "CVE-2021-26411: Internet Explorer mshtml use-after-free" 
has illustrated the root cause: removeAttributeNode() triggers the attribute object nodeValue's valueOf callback. During the callback, clearAttributes() is called manually, which causes the BSTR saved in nodeValue to be released in advance. After the valueOf callback returns, the nodeValue object is not checked if existed, which results in UAF.<br>

The bug fix for this vulnerability in Windows March patch is to add an index check before deleting the object in CAttrArray::Destroy function:<br>
![avatar](/images/RPC-Bypass-CFG/1.png)<br><br>

For such a UAF vulnerability with a controllable memory size, the idea of ​​exploitation is: use two different types of pointers (BSTR and Dictionary.items) to point to the reuse memory, then pointer leak and pointer dereference is achieved via type confusion:<br>
![avatar](/images/RPC-Bypass-CFG/2.png)<br><br>


##  Windows RPC introduction and exploitation
Windows RPC is used to support the scenario of distributed client/server function calls. Based on Windows RPC, the client can call server functions thw same as local function call. The basic architecture of Windows RPC is shown as follows:<br>
![avatar](/images/RPC-Bypass-CFG/3.png)<br><br>

The client/server program passes the calling parameters or return values ​​to the lower-level Stub function. The Stub function is responsible for encapsulating the data into NDR (Network Data Representation) format. Communications through the runtime library is provided by rpcrt4.dll.<br>

An idl example is given below:<br>
```cpp
[
	uuid("1BC6D261-B697-47C2-AF83-8AE25922C0FF"),
	version(1.0)
]

interface HelloRPC
{
	int add(int x, int y);
}
```

When the client calls the add function, the server receives the processing request from rpcrt4.dll and calls rpcrt4!NdrServerCall2:<br>
![avatar](/images/RPC-Bypass-CFG/4.png)<br><br>

rpcrt4!NdrServerCall2 has only one parameter PRPC_MESSAGE, which contains important data such as the function index and parameters. The server RPC_MESSAGE structure and main sub data structure are shown as follows (32 bits):<br>
![avatar](/images/RPC-Bypass-CFG/5.png)<br><br>

As shown in the aforementioned picture, in RPC_MESSAGE structure, the two important variables of function call are Buffer and RpcInterfaceInformation. The Buffer stores the parameters of the function, and RpcInterfaceInformation points to the RPC_SERVER_INTERFACE structure. The RPC_SERVER_INTERFACE structure saves the server program interface information, in which DispatchTable(+0x2c) saves the interface function pointers of the runtime library and the stub function, and InterpreterInfo(+0x3c) points to the MIDL_SERVER_INFO structure. The MIDL_SERVER_INFO structure saves the server IDL interface information, and the DispatchTable(+0x4) saves the pointer array of the server routine functions.<br>

Here is an example to introduce the structure of RPC_MESSAGE:<br>

According to the idl given above, when the client calls add(0x111, 0x222), the server program breaks at rpcrt4!NdrServerCall2:
![avatar](/images/RPC-Bypass-CFG/6.png)<br><br>

It can be seen that the dynamic debugging memory dump is consistent with the RPC_MESSAGE structure analysis, and the add function is stored in MIDL_SERVER_INFO.DispatchTable.<br>

Next, we analyze how rpcrt4!NdrServerCall2 calls the add function according to RPC_MESSAGE:<br>

The rpcrt4!NdrServerCall2 calls rpcrt4!NdrStubCall2 internally. The rpcrt4!NdrStubCall2 calculates the function pointer address based on MIDL_SERVER_INFO.DispatchTable and RPC_MESSAGE.ProcNum, and passes the function pointer, function parameters and parameter length to rpcrt4!Invoke:<br>
![avatar](/images/RPC-Bypass-CFG/7.png)<br><br>

The rpcrt4!Invoke calls the server provided routine function finally:<br>
![avatar](/images/RPC-Bypass-CFG/8.png)<br><br>

Based on above analysis, after achieving the arbitrary memory read/write primitive, we can construct an fake RPC_MESSAGE, set the function pointer and function parameters want to invoke, and call rpcrt4!NdrServerCall2 manually to implement any function execution.<br>

Two problems need to be solved next:<br>
1）How to invoke rpcrt4!NdrServerCall2 in javascript<br>
2）When observing the server routine function call in rpcrt4!Invoke:<br>
![avatar](/images/RPC-Bypass-CFG/9.png)<br><br>

We can see that this is an indirect function call, and there is a CFG check. Therefore, we need to consider how to bypass the CFG protection here after tampering with the MIDL_SERVER_INFO.DispatchTable function pointer.<br>

Let's solve the problem 1 firstly: How to invoke rpcrt4!NdrServerCall2 in javascript?<br>
We can replace the DOM object vtable's function pointer with rpcrt4!NdrServerCall2. Because rpcrt4!NdrServerCall2 is a legal pointer recorded in CFGBitmap, it can pass the CFG check. The sample replacs MSHTML!CAttribute::normalize with rpcrt4!NdrServerCall2, and calls "xyz.normalize()" in javascript to invoke rpcrt4!NdrServerCall2.<br>

Then we solve the problem 2: How to bypass the CFG protection in rpcrt4!NdrServerCall2?<br>
The method in the sample is:<br>
1) Use fake RPC_MESSAGE and rpcrt4!NdrServerCall2 to invoke VirtualProtect, and modify the memory attribute of RPCRT4!__guard_check_icall_fptr to PAGE_EXECUTE_READWRITE
2) Replace the pointer ntdll!LdrpValidateUserCallTarget saved in rpcrt4!__guard_check_icall_fptr with ntdll!KiFastSystemCallRet to kill the CFG check in rpcrt4.dll
3) Restore RPCRT4!__guard_check_icall_fptr memory attribute<br>

```javascript
function killCfg(addr) {
	var cfgobj = new CFGObject(addr)
	if (!cfgobj.getCFGValue()) 
		return
	var guard_check_icall_fptr_address = cfgobj.getCFGAddress()
	var KiFastSystemCallRet = getProcAddr(ntdll, 'KiFastSystemCallRet')
	var tmpBuffer = createArrayBuffer(4)
	call2(VirtualProtect, [guard_check_icall_fptr_address, 0x1000, 0x40, tmpBuffer])
	write(guard_check_icall_fptr_address, KiFastSystemCallRet, 32)
    call2(VirtualProtect, [guard_check_icall_fptr_address, 0x1000, read(tmpBuffer, 32), tmpBuffer])
    map.delete(tmpBuffer)
} 
```
<br>
After solving the two problems, the fake RPC_MESSAGE can be used to invoke any function including the buffer stores the shellcode because CFG check in rpcrt4.dll has been killed. At last, the sample writes the shellcode to the location of msi.dll + 0x5000, and invokes the shellcode through rpcrt4!NdrServerCall2 finally:<br>

```javascript
var shellcode = new Uint8Array([0xcc])
var msi = call2(LoadLibraryExA, [newStr('msi.dll'), 0, 1]) + 0x5000
var tmpBuffer = createArrayBuffer(4)
call2(VirtualProtect, [msi, shellcode.length, 0x4, tmpBuffer])
writeData(msi, shellcode)
call2(VirtualProtect, [msi, shellcode.length, read(tmpBuffer, 32), tmpBuffer])
call2(msi, [])
```
<br>

The exploitation screenshot:<br>
![avatar](/images/RPC-Bypass-CFG/10.png)<br><br>

## Some thoughts
A new method to bypass CFG mitigation by exploiting Windows RPC used in CVE-2021-26411 in the wild sample. This exploitation technology does not need to construct ROP chain, and achieve arbitrary code execution directly by fake RPC_MESSAGE. This exploitation technology is simple and stable. It is reasonable to believe that it will become a new and effective exploitation technology to bypass CFG mitigation.

## References
[1] https://docs.microsoft.com/en-us/windows/win32/secbp/control-flow-guard<br>
[2] https://windows-internals.com/cet-on-windows/<br>
[3] https://docs.microsoft.com/en-us/windows/win32/rpc/rpc-start-page<br>