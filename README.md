# Anti-Sandbox Musings

> Author: Yu Ji

# Introduction

When learning anti-detection techniques, I encountered an unavoidable challenge: anti-sandboxing. When our samples are uploaded to online analysis websites, they undergo dynamic and static analysis within a virtualized environment. This process records sensitive operations to determine whether the sample is malicious software. We've likely all encountered this scenario: CS connects to numerous foreign machines with different usernames and operating systems, yet the heartbeat packets remain unusually short. At this point, we can confidently conclude our sample has been trapped in a sandbox environment. What should we do? Let's explore further by examining the author's musings on anti-sandboxing techniques.

# Sandbox

Before we discuss anti-sandboxing, let's first clarify what a sandbox is. The [National Institute of Standards and Technology (NIST)] (https://csrc.nist.gov/glossary/term/sandbox) defines a sandbox as “a system that allows untrusted applications to run in a highly controlled environment where the application's privileges are restricted to a set of basic computer privileges.”

Sandboxes can actually be categorized into three types: software, hardware, and cloud-based.

Common software includes:[sandboxie](https://sandboxie-plus.com/downloads/) Used to launch programs in a sandbox environment; VMware and Docker are also considered software sandbox implementations.

Hardware solutions are typically sold as enterprise solutions, such as Huawei's.[FireHunter6000](https://e.huawei.com/cn/products/security/firehunter6000)

The cloud-based ones are the sandbox websites we commonly use, such as:

* https://s.threatbook.com/ Microstep Sandbox
* https://www.virustotal.com/ VT
* https://any.run/ Interactive Sandbox
* https://www.joesandbox.com/#windows Joe Sandbox
* https://www.hybrid-analysis.com/ hybrid analysis system
* https://sandbox.dbappsecurity.com.cn/ Anheng Cloud Sandbox
* https://sandbox.ti.qianxin.com/sandbox/page QiAnXin Sandbox
* https://sandbox.freebuf.com/ Freebuf Sandbox
* https://ata.360.net/ 360 Cloud Sandbox
* https://habo.qq.com/ Hubble Sandbox

# Prerequisite

If you want to build anti-sandboxing capabilities for your Trojan sample, ensure the following prerequisites are met:

* Capable of static bypassing

  * Ensure no sensitive information is present in static resources; avoid obfuscation whenever possible.
  * If loading as shellcode, encrypt the shellcode beforehand (avoid using symmetric encryption with short keys).
* No other prerequisites

  * For example, anti-debugging checks are performed before loading the logic
  * Ensures that anti-sandboxing logic is invoked first during program execution

  The author uses Visual Studio 2019 with C++ as the programming language. Readers with other preferences may freely switch to a different IDE or programming language.

# Thought process

## Appetizer

How to counter micro-stepping sandboxing?

First, let's examine the release function of MicroStep. It generates a folder with a random string name under the C drive to run.

![1714200819289](image/Anti-Sandbox/1714200819289.png)

At this point, we can write code that uses simple regular expression matching to bypass the sandbox.

```cpp
std::string workingdir()
{
    char buf[256];
    GetCurrentDirectoryA(256, buf);
    return std::string(buf);
}
bool check_run_path() {
    std::string test(workingdir());
    std::regex pattern("^C:\\\\[A-Za-z0-9_]+");
    if (std::regex_match(test, pattern)) {
        return false;
    }
    else {
        return true;
    }
}
```

Achievements

![1714200965683](image/Anti-Sandbox/1714200965683.png)  微步多年以来都是这样释放样本的，理论上不会失效。接下来会以三个反向介绍反沙箱的思路

## Time-Based Checks

Used for delays. Since sandboxes may accelerate processes or bypass time delays through hooking techniques, it's best to combine these with differential checks.

The delay duration should be sufficiently long, as some virtual machines may take extended periods to complete analysis.

routine

* NtDelayExecution
* WaitForSingleObject
* SetTimer
* SetWaitableTimer
* CreateTimerQueueTimer

Advanced

* Using API Flooding
* GetSystemTimeAdjustment
* Implement your own timer
  * Implementing a Timer Function
  * Using the求算法 to introduce a delay
* Retrieve time from another process For example, scheduled tasks
* select (Windows sockets)

Coordinate

*   Online timestamp queries to determine time differences
    *   NTP
    *   Third-party APIs

I use

* Time Delay and Difference Detection

```cpp
bool check_time() {
    auto url = ("http://api.pinduoduo.com");
    httplib::Client cli(url);
    auto res = cli.Get("/api/server/_stm");
    std::string time_str1;
    if (res->status == 200) {
        for (char c : res->body) {
            if (c >= '0' && c <= '9') {
                time_str1 += c;
            }
        }
    }
    else {
        return false;
    }
    long long api_time1 = std::stoll(time_str1);
    time_t currentTime1 = time(0);
    //开始休眠300秒
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    WaitForSingleObject(hEvent, 300000);//300s
    CloseHandle(hEvent);
    res = cli.Get("/api/server/_stm");
    std::string time_str2;
    if (res->status == 200) {
        for (char c : res->body) {
            if (c >= '0' && c <= '9') {
                time_str2 += c;
            }
        }
    }
    else {
        return false;
    }
    long long api_time2 = std::stoll(time_str2);
    //判断差值
    if (api_time2 - api_time1 > 290000) {
        return true;
    }
    else {
        exit(0);
        return false;
    }
}
```

To determine the system boot time, virtual machines typically run continuously for extended periods. We can use the WINAPI GetTickCount() function for this purpose.

However, if our sample target is to test a server, determining the system boot time becomes ineffective.

## Factor Assessment

Standard

+ Determine CPU core count dwNumberOfProcessors
+ Determine RAM size GlobalMemoryStatus
+ Determine hard drive size PhysicalDrive0
+ Determine system username
  + Previously, there was a dictionary for determining usernames, but now they are generally random numbers like DESKTOP-XXX.
+ Determination Working Group (Domain)

Advanced: This section features a specialized term: **Pocket Litter**

+ Determine desktop file count
  + Most sandboxed desktops have minimal files, featuring various Office software but lacking apps like WeChat or QQ
  + We can determine if files fall below a certain threshold to identify sandboxing
  + Check for presence of WeChat, QQ, WeCom, and other software aligning with typical Chinese user habits
+ Determine temporary file count
  + Conversely, excessive temporary files compared to normal users may indicate sandboxing
+ Detect the number of doc, xls, ppt files in the system
  + A low count may indicate a sandbox environment
+ Detect whether the executable filename has been modified
+ Detect whether the process is running within a specific time window (common in APT attacks, frequently used by HVV)
+ Detect system language via GetSystemDefaultLangID
  + A common tactic used by Russian APTs; if Russian is detected, the process exits
+ Detect whether attached DLLs are on a blacklist
+ Determine IP address
  + Evaluate based on target criteria
  + For example, if targeting mainland China, check for non-domestic IPs to counter foreign sandboxes
  + Alternatively, narrow scope to prefecture-level cities
+ Verify speaker functionality and accessibility
+ Confirm microphone responsiveness
+ Count active foreground windows
  + Typically fewer in virtual machines
+ Detect mouse movement
  + Previously popular method: GetCursorPos
  + After obtaining coordinates, delay twice and calculate the vector. If the result forms a triangular shape, it's likely not a sandbox
  + Listed as sensitive behavior since flagged in the ATT&CK framework
+ Check graphics card VRAM size
  + Typically over 2GB on home PCs, while sandboxes allocate less
+ Check system variables
  + Primarily look for environment variables related to virtual machine files
+ Check CPU temperature

Please note: It is recommended to use the GetSystemFirmwareTable API to retrieve hardware information from SMBIOS.

Using the WMI API will be considered a sensitive operation.

I am using

+ IP detection

```cpp
bool check_ip() {
    auto url = "http://ip-api.com";
    httplib::Client cli(url);
    auto res = cli.Get("/csv");
    std::string ip_str;
    if (res->status == 200) {
        for (char c : res->body) {
            ip_str += c;
        }
    }
    else {
        exit(0);
        return false;
    }
    if (ip_str.find("China") != std::string::npos) {
        //std::cout << "The string contains 'China'." << std::endl;
        return true;
    }
    else {
        //std::cout << "The string does not contain 'China'." << std::endl;
        exit(0);
        return false;
    }
}
```

+ Mouse Detection

```cpp
double distance(POINT p1, POINT p2) {
    double dx = p2.x - p1.x;
    double dy = p2.y - p1.y;
    return sqrt(dx * dx + dy * dy);
}
bool check_mouse() {
    POINT p1, p2, p3;
    GetCursorPos(&p1);
    Sleep(3000);
    GetCursorPos(&p2);
    Sleep(3000); 
    GetCursorPos(&p3);
    double d1 = distance(p1, p2);
    double d2 = distance(p2, p3);
    double d3 = distance(p3, p1);
    // 检查是否能构成一个类三角形
    if ((d1 + d2 > d3) && (d2 + d3 > d1) && (d1 + d3 > d2)) {
        return true;
    }
    else {
        return false;
    }
}
```

## Unorthodox Methods

Other peculiar anti-sandbox techniques exist:

* Volume Inflation
  * Many online anti-sandbox systems have size limits. If your sample exceeds 300MB, it won't be accepted.
* Reverse Collection
  * Write a sample designed to collect sandbox fingerprints, summarizing the sandbox's characteristics for later identification.
* Compression Bomb
  * Deploy a compressed archive bomb to consume server resources.

# Questions

This article will not cover anti-debugging or anti-virtualization techniques. Anti-debugging methods are highly sensitive, while anti-virtualization is often unnecessary since many servers run on simulated cluster virtual machines. Additionally, sensitive sandbox detection methods will not be discussed, as numerous conventional approaches already exist online. In practice, the key to effective sandbox detection lies not in the number of methods employed, but in their simplicity and practicality for real-world application.

# Summary

As sandboxing technology advances, so does the evolution of anti-sandboxing techniques. Currently, our application of sandboxes remains largely mechanical, yet many security firms have begun developing AI-integrated sandbox systems. Therefore, as security researchers, we must continuously enhance our technical capabilities to keep pace with technological progress.

This project has been open-sourced on GitHub. Feel free to open an issue.

https://github.com/yj94/Anti-Sandbox

# Reference

* https://en.wikipedia.org/wiki/Sandbox_(computer_security)
* https://csrc.nist.gov/glossary/term/sandbox
* https://github.com/Hz-36/Anti-Sandbox
* https://github.com/ZanderChang/anti-sandbox
* https://github.com/LordNoteworthy/al-khaser
* https://attack.mitre.org/techniques/T1497
* https://evasions.checkpoint.com

# Statement

This project was first published on the Prophet Community. Please credit the source when reposting! https://xz.aliyun.com/t/14381
