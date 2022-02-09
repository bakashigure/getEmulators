//
// Created by bakashigure on 2/6/2022.
//
#if 1
#define FMT_HEADER_ONLY

#include <vector>
#include <unordered_set>
#include <map>
#include <string>
#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <sstream>
#include <regex>
#include <shlwapi.h>
#include <fstream>
#include "include/fmt_8.1.1/core.h"
#include "include/fmt_8.1.1/os.h"
#include "include/fmt_8.1.1/printf.h"

struct emulator{
    std::string name; // process_name
    std::string ip; // 127.0.0.1
    std::string port; // like 5555
    std::string address; // 127.0.0.1:5555
    std::string pid; // process pid
    std::string adb_path; // adb_path
};

std::string GetProcessPath(const std::string& pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, atoi(pid.c_str()));
    char path[MAX_PATH] = {0};
    GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH);
    return std::string(path);
}

std::string GetRegValue(HKEY hKey, const std::string& strUrl, const std::string& strKey) {
    std::string strValue;
    HKEY hKeyResult = NULL;
    DWORD dwSize = 0;
    DWORD dwDataType = 0;

    if (ERROR_SUCCESS == ::RegOpenKeyEx(hKey, strUrl.c_str(), 0, KEY_QUERY_VALUE, &hKeyResult)) {
        RegQueryValueEx(hKeyResult, strKey.c_str(), 0, &dwDataType, NULL, &dwSize);
        char *lpValue = new char[dwSize];
        memset(lpValue, 0, dwSize * sizeof(char));
        if (ERROR_SUCCESS == RegQueryValueEx(hKeyResult, strKey.c_str(), 0, &dwDataType, (LPBYTE) lpValue, &dwSize)) {
            strValue = lpValue;
        }
        delete[] lpValue;
    }
    RegCloseKey(hKeyResult);
    return strValue;
}

bool bluestackNormal(emulator& e) {   // HD-Player.exe
    std::regex rule(R"(\s*.{3}\s*127.0.0.1:\s*(\d{4,5})\s*)");
    auto buf = popen(fmt::format("netstat -ano | findstr {}", e.pid).c_str(), "r");
    char buffer[1024] = {0};
    std::stringstream ss;
    std::string line;
    std::smatch m;
    while (fgets(buffer, 1024, buf)) {
        ss << buffer;
    }
    if (ss.str().size()<2) return false;
    while (getline(ss, line, '\n')) {
        bool found = std::regex_search(line, m, rule);
        std::cout << found << "\n";
        if (found) {   // m.str(1) 为端口
            e.name = "Bluestack Normal";
            e.ip = "127.0.0.1";
            e.port = m.str(1);
            e.address = e.ip + ":" + e.port;
            std::string adb_dir = GetProcessPath(e.pid);
            e.adb_path = adb_dir.substr(0, adb_dir.size() - 13) + "\\HD-Adb.exe";
        } else return false;
    }
    return true;
}

bool bluestackHyperv(emulator& e,int& index) {
    std::regex rule (R"SB(bst.instance.Nougat64_?\d?.status.adb_port="(\d{4,6})")SB");
    std::smatch result;
    std::string path = GetRegValue(HKEY_LOCAL_MACHINE, "SOFTWARE\\BlueStacks_nxt", "UserDefinedDir");
    path += "\\bluestacks.conf";
    std::stringstream ss;
    std::ifstream conf(path);
    ss<<conf.rdbuf();
    conf.close();
    std::string line(ss.str());
    std::vector<std::string> ports;
    std::string::const_iterator searchStart(line.cbegin());
    while (std::regex_search(searchStart,line.cend(),result,rule))
    {
        ports.emplace_back(result[1]);
        searchStart = result.suffix().first;
        //std::cout<<"____INDEX:\n"<<result[0]<<"\n"<<result[1]<<"\n"<<result[2]<<"\n"<<result[3]<<"\n____\n";
    }
    e.port = ports[index];
    e.address = fmt::format("127.0.0.1:{}",e.port);
    index++;
    return true;
}


int main() {
    std::unordered_set<std::string> emulator_list = {"HD-Player.exe", "LdVBoxHeadless.exe"};
    auto tasklistBuf = popen("tasklist", "r");
    std::string tasklistString;
    std::stringstream tasklistStream;
    char buffer[1024] = {0};
    while (fgets(buffer, 1024, tasklistBuf)) {
        tasklistStream << buffer;
    }
    // std::cout<<tasklistStream.str();
    std::string line;
    int bluestackHypervIndex = 0;
    while (getline(tasklistStream, line, '\n')) {

        std::regex rule("(.{3,25}[^\\s*])\\s*([0-9]*)");
        std::smatch m;
        bool found = std::regex_search(line, m, rule);
        if (found) {
            emulator e = {.name =  m.str(1), .pid=m.str(2)};
            if (m.str(1) == "HD-Player.exe") {
                //std::cout << fmt::format("{} | {} \n", e.name, e.pid);
                if (!bluestackNormal(e))
                    bluestackHyperv(e,bluestackHypervIndex);
                std::cout<<fmt::format("process_name:{}    pid:{}\naddress:{}\nadb_path:{}\n\n",e.name,e.pid,e.address,e.adb_path);
            }
        }
    }

    //std::cout << tasklistString;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, 19244);
    char path[MAX_PATH] = {0};
    GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH);
    //std::cout << path;
    return 0;
}

#endif

