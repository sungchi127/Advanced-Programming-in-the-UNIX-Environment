#include <iostream>
#include <dirent.h>
#include <stdlib.h>
#include <vector>
#include <cstring>
#include <fstream>
using namespace std;
 
string number;
//遍历指定路径下的所有文件，将文件的路径存于vector中
void GetFileNames(string path)
{
    DIR *pDir;
    struct dirent* ptr;
    if(!(pDir = opendir(path.c_str()))){
        cerr<<"error：Folder doesn't Exist!"<<endl;
        return;
    }
    while((ptr = readdir(pDir))!=0) {
        if (strcmp(ptr->d_name, ".") != 0 && strcmp(ptr->d_name, "..") != 0){
            // ptr->d_type == DT_DIR;
            std::ifstream ifs;
            char buffer[8] = {0};
            string filename=path + "/" + ptr->d_name;
            if(ptr->d_type == DT_DIR){
                GetFileNames(filename);
            }
            else{
                ifs.open(filename);
                if (!ifs.is_open()) {
                    cerr << "Failed to open file.\n";
                    // return 1; // EXIT_FAILURE
                }

                ifs.read(buffer, sizeof(buffer));
                // cerr << filename << ": " << buffer <<"\n";
                if(buffer==number){
                    cerr<<"GOOD:"<<filename<<"\n";
                    cout<<filename<<"\n";
                }
                ifs.close();

                // filenames.push_back(path + "/" + ptr->d_name);
            }
        }
    }
    closedir(pDir);
}
 
int main(int argc , char* argv[]) {
    vector<string> file_names;
    string dirpath = argv[1];
    // dirpath=dirpath.substr(1);
    string a2=argv[2];
    number=a2;

    cerr<<"dir: "<<dirpath<<" , number: "<<number<<"\n";

    GetFileNames(dirpath);
    // for(int i = 0; i <file_names.size(); i++)
    // {
    //     cout<<"file:"<<file_names[i]<<endl;
    // }
    cout<<"1";
    return 0;
}
 
 
 