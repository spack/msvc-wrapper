
#include "utils.h"

// String helper methods adding cxx20 features to cxx14
bool startswith(std::string &arg, std::string &match) {
    size_t matchLen = match.size();
    if ( matchLen > arg.size() )
        return false;
    return arg.compare(0, matchLen, match) == 0;
}

bool startswith(std::string &arg, const char * match) {
    return startswith(arg, (std::string)match);
}

bool endswith(std::string &arg, std::string &match) {
    size_t matchLen = match.size();
    if ( matchLen > arg.size() )
        return false;
    return arg.compare(arg.size() - matchLen, matchLen, match) == 0;
}

bool endswith(std::string &arg, char const* match) {
    return endswith(arg, (std::string)match);
}

std::string ConvertWideToANSI(const std::wstring &wstr) {
    int count = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
    std::string str(count, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
    return str;
}

std::wstring ConvertAnsiToWide(const std::string &str) {
    int count = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), NULL, 0);
    std::wstring wstr(count, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), &wstr[0], count);
    return wstr;
}

StrList split(std::string s, std::string delim) {
    size_t pos_start = 0, pos_end;
    size_t delim_len = delim.length();
    std::string token;
    StrList res = StrList();

    while ( (pos_end = s.find(delim, pos_start)) != std::string::npos ) {
        size_t token_len = pos_end - pos_start;
        token = s.substr(pos_start, token_len);
        pos_start = pos_end + delim_len;
        if (token == delim || token.empty())
        {
            continue;
        }
        res.push_back(token);
    }
    res.push_back(s.substr(pos_start));
    return res;
}