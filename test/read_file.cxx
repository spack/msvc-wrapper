#include <fstream>
#include <string>
#include <iostream>

#define IMAGE_ARCHIVE_START_SIZE 8

struct Coff {
    char signature[IMAGE_ARCHIVE_START_SIZE];
};

void ReadSig(char *sig, std::fstream &stream){
    stream.read(sig, 8);
}

int main(int argc, char ** argv)
{
    std::string filename(argv[1]);
    std::fstream in(filename);
    if(!in){
        std::cerr << "cannot open file" << "\n";
        return 1;
    }
    Coff coff;
    ReadSig(&coff.signature, in);
    std::cout << coff.signature << "\n";
    return 0;

}