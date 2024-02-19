# Chakra Type Confusions

This repository contains PoCs for type confusion vulnerabilities in the ChakraCore engine used by Microsoft Edge (EdgeHTML version, not Chromium-based Edge).

The PoCs execute dummy code (specifically an `int 3` followed by `nop`) in a Just-In-Time (JIT) compilation process.

To verify the PoCs, attach a debugger to a JIT compilation process (one of the `MicrosoftEdgeCP.exe` processes) and execute the PoCs.


### Tested Environment

- Windows 10 Version 1703 (OS Build 15063.0)


## Type Confusion Vulnerabilities

- [CVE-2019-0567](https://bugs.chromium.org/p/project-zero/issues/detail?id=1702)
  - InitProto
  - NewScObjectNoCtor
- [CVE-2019-0539](https://bugs.chromium.org/p/project-zero/issues/detail?id=1703)
- [CVE-2018-8617](https://bugs.chromium.org/p/project-zero/issues/detail?id=1705)


## References

- [Exploit Development: Browser Exploitation on Windows - CVE-2019-0567, A Microsoft Edge Type Confusion Vulnerability](https://connormcgarr.github.io/type-confusion-part-1/)
- [CVE-2019-0539 to Remote Code Execution (RCE)](https://perception-point.io/blog/cve-2019-0539-remote-code-execution/)
- [Bypassing Mitigations by Attacking JIT Server in Microsoft Edge](https://github.com/googleprojectzero/p0tools/tree/master/JITServer)
