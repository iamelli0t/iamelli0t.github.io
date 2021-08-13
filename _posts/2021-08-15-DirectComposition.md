---
layout: post
toc: true
title: "Analysis of DirectComposition Binding and Tracker object vulnerability"
tags: [windows, kernel, DirectComposition]
author:
  - iamelli0t
---

## DirectComposition introduction
Microsoft DirectComposition is a Windows component that enables high-performance bitmap composition with transforms, effects, and animations. Application developers can use the DirectComposition API to create visually engaging user interfaces that feature rich and fluid animated transitions from one visual to another.[1]<br>

DirectComposition API provides COM interface via dcomp.dll, calls win32kbase.sys through win32u.dll export function, and finally sends data to client program dwm.exe (Desktop Window Manager) through ALPC to complete the graphics rendering operation:<br>
![avatar](/images/DirectComposition/1.png)<br><br>

win32u.dll (Windows 10 1909) provides the following export functions to handle DirectComposition API:<br>
![avatar](/images/DirectComposition/2.png)<br><br>

The three functions related to trigger vulnerability are: NtDCompositionCreateChannel，NtDCompositionProcessChannelBatchBuffer and NtDCompositionCommitChannel: <br>
(1) **NtDCompositionCreateChannel** creates a channel to communicate with the kernel: <br>
```cpp
typedef NTSTATUS(*pNtDCompositionCreateChannel)(
	OUT PHANDLE hChannel,
	IN OUT PSIZE_T pSectionSize,
	OUT PVOID* pMappedAddress
	);
```

(2) **NtDCompositionProcessChannelBatchBuffer** batches multiple commands: <br>
```cpp
typedef NTSTATUS(*pNtDCompositionProcessChannelBatchBuffer)(
    IN HANDLE hChannel,
    IN DWORD dwArgStart,
    OUT PDWORD pOutArg1,
    OUT PDWORD pOutArg2
    );
```

The batched commands are stored in the pMappedAddress memory returned by NtDCompositionCreateChannel. The command list is as follows:<br>
```cpp
enum DCOMPOSITION_COMMAND_ID
{
	ProcessCommandBufferIterator,
	CreateResource,
	OpenSharedResource,
	ReleaseResource,
	GetAnimationTime,
	CapturePointer,
	OpenSharedResourceHandle,
	SetResourceCallbackId,
	SetResourceIntegerProperty,
	SetResourceFloatProperty,
	SetResourceHandleProperty,
	SetResourceHandleArrayProperty,
	SetResourceBufferProperty,
	SetResourceReferenceProperty,
	SetResourceReferenceArrayProperty,
	SetResourceAnimationProperty,
	SetResourceDeletedNotificationTag,
	AddVisualChild,
	RedirectMouseToHwnd,
	SetVisualInputSink,
	RemoveVisualChild
};
```
The commands related to trigger vulnerability are: **CreateResource**, **SetResourceBufferProperty**, **ReleaseResource**. The data structure of different commands is different:<br>
![avatar](/images/DirectComposition/3.png)<br><br>

(3) **NtDCompositionCommitChannel** serializes batch commands and sends them to dwm.exe for rendering through ALPC: <br>
```cpp
typedef NTSTATUS(*pNtDCompositionCommitChannel)(
	IN HANDLE hChannel,
	OUT PDWORD out1,
	OUT PDWORD out2,
	IN DWORD flag,
	IN HANDLE Object
	);
```
<br>

## CInteractionTrackerBindingManagerMarshaler::SetBufferProperty process analysis 
First use **CreateResource** command to create **CInteractionTrackerBindingManagerMarshaler** resource (ResourceType = 0x59, hereinafter referred to as "Binding") and **CInteractionTrackerMarshaler** resource (ResourceType = 0x58, hereinafter referred to as "Tracker").<br>
Then call the **SetResourceBufferProperty** command to set the Tracker object to the Binding object's BufferProperty.<br> This process is handled by the function **CInteractionTrackerBindingManagerMarshaler::SetBufferProperty**, which main process is as follows:<br>
![avatar](/images/DirectComposition/4.png)<br><br>

The key steps are as follows:<br>
(1) Check the input buffer subcmd == 0 && bufsize == 0xc<br>
(2) Get Tracker objects tracker1 and tracker2 from channel-> resource_list (+0x38) according to the resourceId in the input buffer<br>
(3) Check whether the types of tracker1 and tracker2 are CInteractionTrackerMarshaler (0x58)<br>
(4) If binding->entry_count (+0x50) > 0, find the matched TrackerEntry from binding->tracker_list (+0x38) according to the handleID of tracker1 and tracker2, then update TrackerEntry->entry_id to the new_entry_id from the input buffer<br>
(5) Otherwise, create a new TrackerEntry structure. If tracker1->binding == NULL || tracker2->binding == NULL, update their binding objects<br><br>

After SetBufferProperty, a reference relationship between the binding object and the tracker object is as follows:<br>
![avatar](/images/DirectComposition/5.png)<br><br>

When use **ReleaseResource** command to release the Tracker object, the **CInteractionTrackerMarshaler::ReleaseAllReferencescalled** function is called. ReleaseAllReferences checks whether the tracker object has a binding object internally:<br>
![avatar](/images/DirectComposition/6.png)<br><br>

If it has:<br>
(1) Call **RemoveTrackerBindings**. In RemoveTrackerBindings, TrackerEntry.entry_id is set to 0 if the resourceID in tracker_list is equal to the resourceID of the freed tracker. Then call **CleanUpListItemsPendingDeletion** to delete the TrackerEntry which entry_id=0 in tracker_list:<br>
![avatar](/images/DirectComposition/7.png)<br><br>
(2) Call **ReleaseResource** to set refcnt of the binding object minus 1.<br>
![avatar](/images/DirectComposition/8.png)<br><br>
(3) tracker->binding (+0x190) = 0<br><br>

According to the above process, the input command buffer to construct a normal SetBufferProperty process is as follows:<br>
![avatar](/images/DirectComposition/9.png)<br><br>

After SetBufferProperty, the memory layout of binding1 and tacker1, tracker2 objects is as follows:<br>
![avatar](/images/DirectComposition/10.png)<br><br>

After ReleaseResource tracker2, the memory layout of binding1, tacker1, and tracker2 objects is as follows:<br>
![avatar](/images/DirectComposition/11.png)<br><br>


## CVE-2020-1381
Retrospective the process of **CInteractionTrackerBindingManagerMarshaler::SetBufferProperty**, when new_entry_id != 0, a new TrackerEntry structure will be created:<br>
![avatar](/images/DirectComposition/12.png)<br><br>


If tracker1 and tracker2 have been bound to binding1 already, after binding tracker1 and tracker2 to binding2, a new TrackerEntry structure will be created for binding2. Since tracker->binding != NULL at this time, tracker->binding will still save binding1 pointer and will not be updated to  binding2 pointer. When the tracker is released, binding2->entry_list will retain the tracker's dangling pointer.<br><br>
Construct an input command buffer which can trigger the vulnerability as follows:<br>
![avatar](/images/DirectComposition/13.png)<br><br>

Memory layout after ReleaseResource tracker1:<br>
![avatar](/images/DirectComposition/14.png)<br><br>

It can be seen that after ReleaseResource tracker1, binding2->track_list[0] saves the dangling pointer of tracker1.<br><br>

## CVE-2021-26900
According to analyze the branch of 'the new_entry_id != 0', the root cause of CVE-2020-1381 is when creating TrackerEntry, it didn't check the tracker object which has been bound to the binding object. The patch adds a check for tracker->binding when creating TrackerEntry:<br>
![avatar](/images/DirectComposition/15.png)<br><br>

CVE-2021-26900 is a bypass of the CVE-2020-1381 patch. The key point to bypass the patch is if the condition of tracker->binding==NULL can be constructed after the tracker is bound to the binding object.<br>
The way to bypass is in the 'update TrackerEntry' branch:<br>
![avatar](/images/DirectComposition/16.png)<br><br>

When TrackerEntry->entry_id == 0, **RemoveBindingManagerReferenceFromTrackerIfNecessary** function is called. It checks if entry_id==0 internally, then call **SetBindingManagerMarshaler** to set tracker->binding=NULL:<br>
![avatar](/images/DirectComposition/17.png)<br><br>


Therefore, by setting entry_id=0 manually, the status of tracker->binding == NULL can be obtained, which can be used to bypass the CVE-2020-1381 patch.<br><br>
Construct an input command buffer which can trigger the vulnerability as follows:<br>
![avatar](/images/DirectComposition/18.png)<br><br>

After setting entry_id=0 manually, the memory layout of binding1 and tracker1:<br>
![avatar](/images/DirectComposition/19.png)<br><br>

At this time, binding1->TrackerEntry still saves the pointer of tracker1, but tracker1->binding = NULL. Memory layout after ReleaseResource tracker1:
![avatar](/images/DirectComposition/20.png)<br><br>

It can be seen that after ReleaseResource tracker1, binding1->track_list[0] saves the dangling pointer of tracker1.<br><br>

## CVE-2021-26868
Retrospective the method in CVE-2021-26900 which sets entry_id=0 manually to get tracker->binding == NULL status to bypass the CVE-2020-1381 patch and the process of **CInteractionTrackerMarshaler::ReleaseAllReferences:ReleaseAllReferences** which checks that if the tracker object has a binding object, and then deletes the corresponding TrackerEntry.<br><br>
So when entry_id is set to 0 manually, tracker->binding will be set to NULL. When the tracker object is released via ReleaseResource command, the TrackerEntry saved by the binding object will not be deleted, then a dangling pointer of the tracker object will be obtained again.<br><br>
Construct an input command buffer which can trigger the vulnerability as follows:<br>
![avatar](/images/DirectComposition/21.png)<br><br>

Memory layout after ReleaseResource tracker1:<br>
![avatar](/images/DirectComposition/22.png)<br><br>

It can be seen that after ReleaseResource tracker1, binding1->track_list[0] saves the dangling pointer of tracker1.<br><br>

## CVE-2021-33739
CVE-2021-33739 is different from the vulnerability in win32kbase.sys introduced in previous sections. It is a UAF vulnerability in dwmcore.dll of the dwm.exe process. The root cause is in ReleaseResource phase of CloseChannel. In **CInteractionTrackerBindingManager::RemoveTrackerBinding** function call, when the element Binding->hashmap(+0x40) is deleted, the hashmap is accessed directly without checking whether the Binding object is released, which causes the UAF vulnerability.<br><br>

Construct an input command buffer which can trigger the vulnerability as follows:<br>
![avatar](/images/DirectComposition/23.png)<br><br>

According to the previous analysis, in the normal scenario of **CInteractionTrackerBindingManagerMarshaler::SetBufferProperty** function call, the Binding object should be bound with two different Tracker objects. However, if it is bound with the same Tracker object:<br><br>
(1) **Binding phase**:<br>
**CInteractionTrackerBindingManager::ProcessSetTrackerBindingMode** function is called to process binding opreation, which calls **CInteractionTrackerBindingManager::AddOrUpdateTrackerBindings** function internally to update Tracker->Binding (+0x278). When Tracker has already be bound with the current Binding object, the binding operation will not be repeated:<br>
![avatar](/images/DirectComposition/24.png)<br><br>

Therefore, if the same Tracker object is bound already, the Binding object will not be bound again, then the refcnt of the Binding object will only be increased by 1 finally:
![avatar](/images/DirectComposition/25.png)<br><br>

(2) **Release phase**:<br>
After PreRender is finished, **CComposition::CloseChannel** will be called to close the Channel and release the Resource in the Resource HandleTable. The Binding object will be released firstly, at this time Binding->refcnt = 1:<br>
![avatar](/images/DirectComposition/26.png)<br><br>

Then the Tracker object will be released. **CInteractionTrackerBindingManager::RemoveTrackerBindings** will be called to release Tracker->Binding:<br>
![avatar](/images/DirectComposition/27.png)<br><br>

Three steps are included:<br>
(1) Get the Tracker object from the TrackerEntry<br>
(2) Erase the corresponding Tracker pointer from Binding->hashmap (+0x40)<br>
(3) Remove Tracker->Binding (Binding->refcnt --) from the Tracker object<br><br>

The key problem is: After completing the cleanup of the first Tracker object in TrackerEntry, the Binding object may be released already. When the second Tracker object is prepared to be cleared, because the Binding object has been released, the validity of the Binding object does not be checked before the Binding->hashmap is accessed again, which result in an access vialation exception:<br>
![avatar](/images/DirectComposition/28.png)<br><br>

## Exploitation: Another way to occupy freed memory
For the kernel object UAF exploitation, according to the publicly available exploit samples[5], the Palette object is used to occupy the freed memory: <br>
![avatar](/images/DirectComposition/29.png)<br><br>

Use **CInteractionTrackerBindingManagerMarshaler::EmitBoundTrackerMarshalerUpdateCommands** function to access the placeholder objects:<br>
![avatar](/images/DirectComposition/30.png)<br><br>

The red box here is the virtual function **CInteractionTrackerMarshaler::EmitUpdateCommands** of tracker1, tracker2 object (vtable + 0x50). Because the freed Tracker object has been reused by Palette, the program execution flow hijacking is achieved by forging a virtual table and writing other function pointers to fake Tracker vtable+0x50.<br>
The sample selects **nt!SeSetAccessStateGenericMapping**:<br>
![avatar](/images/DirectComposition/31.png)<br><br>

With the 16-byte write capability of nt!SeSetAccessStateGenericMapping, it modifies _KTHREAD->PreviousMode = 0 to inject shellcode into Winlogon process to complete the privilege escalation.<br><br>

**Another way to occupy freed memory**<br>

The exploitation of Palette object is relatively common, is there some object with user-mode controllable memory size in the DirectComposition component can be exploited?<br>

The Binding object and Tracker object we discussed before are belonged to the Resource of DirectComposition.  DirectComposition contains many Resource objects, which are created by **DirectComposition::CApplicationChannel::CreateInternalResource**:<br>
![avatar](/images/DirectComposition/32.png)<br><br>

Each Resource has a BufferProperty, which is set by **SetResourceBufferProperty** command. So our object is to find one Resource which can be used to allocate a user-mode controllable memory size through the **SetResourceBufferProperty** command. Through searching, I found **CTableTransferEffectMarshaler::SetBufferProperty**. The command format is as follows:<br>
![avatar](/images/DirectComposition/33.png)<br><br>

When subcmd==0, the bufferProperty is stored at CTableTransferEffectMarshaler+0x58. The size of the bufferProperty is set by the user-mode input bufferSize, and the content is copied from the user-mode input buffer:<br>
![avatar](/images/DirectComposition/34.png)<br><br>

Modify the original sample and use the propertyBuffer of CTableTransferEffectMarshaler to occupy freed memory:<br>
![avatar](/images/DirectComposition/35.png)<br>
![avatar](/images/DirectComposition/36.png)<br><br>

By debugging, we can see that the propertyBuffer of CTableTransferEffectMarshaler occupies the freed memory successfully:<br>
![avatar](/images/DirectComposition/37.png)<br><br>

Finally, successful exploitation screenshot:<br>
![avatar](/images/DirectComposition/38.png)<br><br>

## References
[1] https://docs.microsoft.com/en-us/windows/win32/directcomp/directcomposition-portal<br>
[2] https://www.zerodayinitiative.com/blog/2021/5/3/cve-2021-26900-privilege-escalation-via-a-use-after-free-vulnerability-in-win32k<br>
[3] https://github.com/thezdi/PoC/blob/master/CVE-2021-26900/CVE-2021-26900.c<br>
[4] https://ti.dbappsecurity.com.cn/blog/articles/2021/06/09/0day-cve-2021-33739/<br>
[5] https://github.com/Lagal1990/CVE-2021-33739-POC<br>
