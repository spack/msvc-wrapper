#include "toolchain_factory.h"
#include "toolchain.h"
#include "winrpath.h"
#include "utils.h"
#include "execute.h"


class TestUtils {
public:
    static bool test_startswith(const std::string &arg, const std::string &match);
    static bool test_endswith(const std::string &arg, const std::string &match);
    static bool test_split(const std::string &s, const std::string &delim);
    static bool test_strip(const std::string &s, const std::string &substr);
    static bool test_join(const StrList &str, const std::string &join_char);
    static bool test_isRelocate(const char *arg);
    static bool test_parseRelocate(const char ** arg, int argc);
};


class TestToolChainFactory {
public:
    static bool test_ParseToolChain(char const * const * argv);
};

class TestCoffReader {
    static bool read_sig();
};

class TestCoffParser {
    static bool test_is_imp_lib();
    static bool test_normalize_name();
    static bool test_parse();
};

class TestLinkerInvocation {
    static bool test_is_exe_link();
    static bool test_parse();
};

class TestLibRename {
    static bool test_compute_rename_line();
    static bool test_compute_def_line();
    static bool test_executeLibRename();
    static bool test_computeDefFile();
};

class TestExecute {
    static bool test_execute();
};


int main(int argc, char ** argv)
{
    

    return 0;
}