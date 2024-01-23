# Rootkit_Hooking
  In order to make more people know about the techniques used by rootkits to intercept function calls
  
  In order to get a better understanding of the attack surface,i've found some pictures about a call 
  to the WriteFile function in kernel32.dll.



![RootkitHooking](https://github.com/0xp17j8/Rootkit_Hooking/assets/111459558/e537be09-a422-4438-b9e5-1a67de77d366)



___________________________________________________________________________________

- 1st :
  WriteFile is just a simple wrapper for NtWriteFile.

  It can be hooked with inline ,IAT ,EAT hooks and so on.

  if you hooked this function ,it would intercept all calls to WriteFile in whichever process the hooks are placed.
  All paths used inside kernel32 are generally Dos Paths (C:\file.txt).

- 2nd :
  NtWriteFile is a small stub that sets the EAX register to a 32bit value,then calls KiFastSystemCall.

  It can also be hooked with inline ,IAT ,EAT hooks too.
  Hooking this function will intercept all calls to CreateFile, NtWriteFile or ZwWriteFile in whichever process the hooks are placed.

  All paths used by ntdll file functions are generally NT Paths (\??\C:\file.txt).

- and then

  In order to call KiFastSystemCall ,NtWriteFile moves the address 0x7FFE0300 (KiFastSystemCall / KiFastSystemCall Pointer) into the EDX register, then it does "call edx" or "call dword ptr [edx]"

  The rootkit could replace the address 0x7FFE0300 within the NtWriteFile function body in order to hook it.
  Hooking this function will intercept all calls to CreateFile, NtWriteFile or ZwWriteFile in whichever process the hooks are placed.
  All paths used by ntdll file functions are generally NT Paths (\??\C:\file.txt).

- 3rd :
  KiFastSystemCall is a small stub that moves the stack pointer into the EDX register then executes the sysenter.

  The stub is only 5 bytes in size and the last instruction (RETN) is pointed to by KiFastSystemCallRet, this only leaves 4 writable bytes (not enough space for a near call/jmp). Furthermore, the address is hard-coded which makes IAT or EAT hooks impossible. 

  Sometimes the KiFastSystemCall stub resides in KUSER_SHARED_DATA, in which case it is not writable from usermode. 

  By hooking this function, the rootkit gains the ability to intercept all user mode calls to kernel functions.

- 4th :

  The SYSENTER instruction is what transfers execution from user mode to kernel mode, in order to execute an kernel function. when the instruction is executed, the CPU sets the code segment to the content  of the SYSENTER_CS register, the stack pointer to the content of the SYSENTER_ESP register, and the EIP to the content of the SYSENTER_EIP register. The SYSENTER_EIP register points to the KiFastCallEntry function which is in ntoskrnl, as a result of this, the cpu will begin to execute KiFastCallEntry.

  These registers are known as MSRs (Model Specific Register), they are only readable by using the CPU instruction RDMSR (Read MSR) and writable using the WRMSR (Write MSR) instruction. These instructions are both privileged (can only be executed from Ring 0) therefore, in order to hook, a kernel driver must be loaded.

  By modifying the SYSENTER_EIP, the rootkit gains the ability to intercept all user mode calls to kernel functions, but we cannot intercept any kernel mode calls, because only user mode call use SYENTER.

- 5th :

  KiFastCallEntry is responsible for taking the 32bit value from the EAX register (this is the value we mentioned in 2nd). The first 11 bits are the ordinal of the SSDT function to use (SSDT_Address+(Ordinal*4)), the 12th and 13th byte determine which SSDT to use, the rest of the bits are ignored. Once the function has worked out which SSDT to use, it calls the address at the given ordinal in the table.

  It can be hooked with an inline hook.

  By hooking this function, the rootkit can intercept all user mode calls to kernel functions, as well as all kernel mode calls to functions starting with Zw (such as ZwCreateFile,ZwCreateKey and so on), but not those starting with Nt (sush as NtOpenProcess , NtOpenFile and so on).

- and 

  Because the SSDT is a table of system function pointers, it is also possible to hook calls by replacing the pointer within the SSDT. For every kernel function in ntdll, there is an equivalent pointer within the SSDT, therefore we can hook any function by replacing the pointer. We are also able to hook all kernel mode calls to functions starting with Zw using this method, however, we cannot hook kernel mode calls to functions starting with Nt.

- 6th :

  NtWriteFile...Again. We saw a call to NtWriteFile in 2nd, however that was just an ntdll.dll stub to enter into kernel mode, this is the actual NtWriteFile call pointed to by the address at the given SSDT ordinal.

  NtWriteFile builds an IRP (I/O Request packet,I/O = Input and Output) and supplies it to IopSynchronousServiceTail, it also passes a device object associated with the file being written.

  Can be hooked with an inline hook.

  By hooking this function, the rootkit can intercept user mode and kernel mode calls to NtWriteFile and ZwWriteFile.

- and
  
  IopSynchronousServiceTail may only be used on certain versions of windows, it is just a simple wrapper for IofCallDriver.

- 7th :

  IofCallDriver takes a device object pointer (PDEVICE_OBJECT) and IRP pointer (PIRP) (both supplied by NtWriteFile). The device object contains a pointer to the driver object of the driver associated with that device (PDRIVER_OBJECT). The driver object contains a member called "MajorFunction", this is an array of 28 driver defined function pointers (a bit like an EAT or the SSDT), Here is a full list of IRP major function names.(https://pastebin.com/Pcce2VAm)

  IofCallDriver will call one of the IRP major functions, based on which one is specified by the "MajorFunction" member in the IO_STACK_LOCATION for the supplied IRP.

  In the case of file operations, the device object given by NtWriteFile will nearly always be \filesystem\ntfs (aka ntfs.sys) or a filter device attached to \FileSystem\Ntfs, because filter drivers pass on the call to the device below below them until it gets to \FileSystem\Ntfs, we can assume the call will always end up at \filesystem\ntfs unless one of the filter drivers cancels it.

  By hooking IofCallDriver, the rootkit can intercept practically any call to any driver. In order to only intercept calls to a certain driver, the rootkit can check the "DriverName" member pointed to by the driver object which is pointed to by the device object.  Alternatively to intercept calls to a certain device, the rootkit could call ObQueryNameString on the device object (It is important to note that not all devices have names). The rootkit can also filter only specific IRP major function calls, this is done by calling "IoGetCurrentIrpStackLocation" on the IRP pointer, then checking the "MajorFunction" member of the returned IO_STACK_LOCATION. 

- 8th :

  The IRP_MJ_WRITE function is responsible for writing files within the filesystem. 

  By attaching a filter device to the device stack of \FileSystem\Ntfs or by replacing an IRP major function pointer with one of its own, the rootkit can intercept any call to \FileSystem\Ntfs. In order to intercept NtWriteFile calls, the rootkit would need to inspect IRP_MJ_WRITE calls in the filter device, or replace the IRP_MJ_WRITE pointer in the driver object.

- 9th :

  This refers to the volume and partition drivers that are used by \FileSystem\Ntfs, these are not normally targeted by rootkits, therefore i have left them out. 

  These drivers can be hooked in the same way as 8th.

- 10th :

  The NTFS filesystem uses the IRP_MJ_WRITE major function of the class driver "\Driver\Disk" (aka disk.sys), in order to write a disk. Because \Driver\Disk is much lower level than the NTFS filesystem driver, there are no file name, instead it is only possible to work with LBAs (Logical Block Addresses). Logical Block Addressing in a linear method of addressing the disk by sectors, each sector is usually 512, 1024, 2048, or 4096 bytes. The sector number starts at 0 (Master Boot Record) and goes up to whatever, depending on the size of the disk.  

  Hooking of drivers lower than ntfs.sys is usually only seen in kernel mode payload drivers used by bootkits. This is due to the fact that bootkits tend to only work with files outside of the NTFS filesystem, therefore not having to worry with translating file names to LBAs.  

- 11th :

  The disk subsystem refers to any driver(s) below disk.sys, generally this a port/miniport driver, which is a hardware or protocol specific driver. In most cases this will be atapi.sys or scsiport.sys which are for ATA and SCSI complaint disk devices. 

  At this level a new IRP major function is used, IRP_MJ_SCSI, which is an alias for IRP_MJ_INTERNAL_DEVICE_CONTROL. Here, the rootkit will have to work with SCSI_REQUEST_BLOCK parameters, which further complicates things compared to a disk.sys hook. 

  Any port/miniport hooks are usually only found in advanced kernel mode payload drivers used by rootkits. 


___________________________________________________________________________________


# Conclusion :

  The term "kernel function" refers to any function beginning with Nt or Zw. I call these kernel functions because the code resides in the kernel, for a user mode application to call one of these functions, it must enter the kernel via SYSENTER.


  Only 1st, 2nd, and 3rd can be hooked from user mode, the rest require a kernel mode driver.

  The reason hooks places at 5th cannot intercept kernel mode calls to functions starting with Nt is due to how these functions work. Any function beginning with Nt, when called from kernel mode refers to the actual function within ntoskrnl. 

  However, when a function beginning with Zw is called from kernel mode, it sets the EAX register to the same number that was set in 2th, then it calls KiSystemService. KiSystemService falls into KiFastCallEntry, I use the word fall, because it does not call or jmp, KiFastCallEntry is at an an offset into KiSystemService, thus 

  KiFastCallEntry is actually a part of the KiSystemService Function. If you are still confused, the above graph should help.

  In user mode both Nt and Zw calls follow exactly the same path. Again, refer to the above graph if you are confused.

  By hooking at a certain point in the flow chart, the rootkit is able to accept all calls to that point and from above it. In other words, by hooking at 3 the rootkit can intercept all successful calls made to 3rd, 2nd, and 1st.

___________________________________________________________________________________

- Happy Hacking






