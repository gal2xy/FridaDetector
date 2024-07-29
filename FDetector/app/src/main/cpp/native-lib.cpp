#include <jni.h>
#include <string>
#include <dirent.h>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <android/log.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <pthread.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__)

#define TAG "FridaDetector"


void* detectFridaLoop();
bool detectByProcessName();
bool detectByDefaultPort();
bool detectByDBus();
bool detectByMaps();
bool detectByTask();
bool detectByScanfMemory();

void* detectFridaLoop(void *){
    LOGD("%s => Create pthread success", TAG);
    while (true) {
        detectByMaps();
//        if (detectByDefaultPort()){
//
//        } else if (detectByProcessName()){
//
//        } else if (detectByProcessName()){
//
//        } else if (detectByDBus()){
//
//        } else if (detectByMaps()){
//
//        } else if (detectByTask()){
//
//        } else if (detectByScanfMemory()){
//
//        }
    }
}

//进程名检测
bool detectByProcessName(){

    std::vector<std::string> pids;
    std::string target_name = "frida";
    DIR* proc_dir = opendir("/proc");
    std::string current_pid = std::to_string(getpid());//当前进程pid

    //获取所有进程id
    if (proc_dir != nullptr){

        struct dirent* entry;
        while((entry = readdir(proc_dir)) != nullptr){
            // 文件是否是目录
            if (entry->d_type == DT_DIR){
                std::string dir_name(entry->d_name);
                //如果目录名是数字,则为进程文件，还需要排除当前进程，因为当前进程的应用名为FridaDetector,包含目标字符串
                if (std::all_of(dir_name.begin(), dir_name.end(), ::isdigit) && dir_name != current_pid) {
                    pids.push_back(dir_name);
                }
            }
        }
        closedir(proc_dir);

    }

    //判断进程名是否包含frida字样
    for (int i = 0; i < pids.size(); i++) {

        //创建输入文件流对象, 用于读取数据
        std::string comm_path = "/proc/" + pids[i] + "/comm";
        std::ifstream comm_file(comm_path);

        if (comm_file.is_open()) {//是否成功打开对应文件
            std::string process_name;
            std::getline(comm_file, process_name);//读一行
            comm_file.close();
            LOGD("%s => %s: pid is %s", TAG, process_name.c_str(), pids[i].c_str());
            if (process_name.find(target_name) != std::string::npos) {
                LOGD("%s => Found frida-server: pid is %s", TAG, pids[i].c_str());
                return true;
            }
        }

    }

    return false;

}

//端口检测
bool detectByDefaultPort(){

    struct sockaddr_in sa;
    int sock = socket(AF_INET , SOCK_STREAM , 0);

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27047);
    inet_aton("127.0.0.1", &(sa.sin_addr));

    if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {
        LOGD("%s => Found frida-server: running on default port", TAG);
        return true;
    }

    return false;

}

//d-bus 通信协议检测
bool detectByDBus(){

    int sock;
    struct sockaddr_in sa;
    char res[7];

    //初始化 sockaddr_in 结构体
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;//AF_INET表示使用 IPv4 地址
    inet_aton("127.0.0.1", &sa.sin_addr);//将 IP 地址字符串 "127.0.0.1" 转换为网络字节序的二进制形式, 并将其存储在 sa.sin_addr 中

    //遍历端口，发送d-bus认证消息，回复了REJECT的端口就是frida-server
    for (int i = 0; i <= 65535; ++i) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        sa.sin_port = htons(i);//设置端口号， htons(i) 将主机字节序转换为网络字节序
        //尝试使用 connect 函数连接到指定的 IP 地址和端口号
        if (connect(sock, (struct sockaddr*)(&sa), sizeof sa) != -1){

            LOGD("%s => Connect on port %d", TAG, i);

            memset(res, 0, 7);

            //发送 d-bus 认证消息
            send(sock, "\x00", 1, NULL);
            send(sock, "AUTH\r\n", 6, NULL);

            usleep(1000); // Give it some time to answer
            LOGD("%s => send Message on port %d", TAG, i);
            //接收数据到res中
            //接收不到消息！！！
            if (recv(sock, res, 6, MSG_DONTWAIT) != -1){
                LOGD("%s => recv Message on port %d: %s", TAG, i, res);
                if (strcmp(res, "REJECT") == 0){
                    LOGD("%s => Found frida-server: running on port %d", TAG, i);
                    close(sock);
                    return true;
                }
            }else{
                LOGD("%s => can't recv Message on port %d", TAG, i);
            }
            close(sock);
        }
    }

    return false;

}

//maps文件扫描 (成功！)
bool detectByMaps(){

    std::ifstream maps_file("/proc/self/maps");

    if (maps_file.is_open()) {
        std::string line;
        while (std::getline(maps_file, line)) {
            if (line.find("frida") != std::string::npos) {
                LOGD(" %s => Found Frida agent in current process by scanf /proc/self/maps", TAG);
                maps_file.close();
                return true;
            }
        }
        maps_file.close();
    }

    return false;

}

//task目录扫描(成功！！！)
bool detectByTask(){

    //获取当前线程的task目录
    DIR* task_dir = opendir("/proc/self/task");
    std::vector<std::string> pids;
    std::string current_pid = std::to_string(getpid());//当前进程pid

    if (task_dir != nullptr) {
//        LOGD(" %s => open /proc/self/task", TAG);
        struct dirent* entry;
        while((entry = readdir(task_dir)) != nullptr){
            if (entry->d_type == DT_DIR){
                std::string dir_name(entry->d_name);
                //如果目录名是数字,则为进程目录
                if (std::all_of(dir_name.begin(), dir_name.end(), ::isdigit)) {
                    pids.push_back(dir_name);
                }
            }
        }
        closedir(task_dir);
    }

    for (int i = 0; i < pids.size(); i++) {

        std::string comm_path = "/proc/self/task/" + pids[i] + "/comm";
        std::ifstream comm_file(comm_path);

        //打开comm文件，查看进程名
        if (comm_file.is_open()) {

//            LOGD(" %s => open /proc/self/task/%s/comm", TAG, pids[i].c_str());
            std::string process_name;
            std::getline(comm_file, process_name);//读一行
            comm_file.close();

            if (process_name.find("gmain") != std::string::npos || process_name.find("gdbus") != std::string::npos
                || process_name.find("gum-js-loop") != std::string::npos || process_name.find("pool-frida") != std::string::npos) {

                LOGD("%s => Found Frida agent in current process by scanf /proc/self/task, process_name: %s", TAG, process_name.c_str());
                return true;

            }
        }
    }

    return false;

}

//内存扫描(成功！！！)
bool detectByScanfMemory(){

    std::string target_name = "LIBFRIDA";//可指定多个特征字符串
    char permission[512];
    unsigned long start, end;
    std::ifstream maps_file("/proc/self/maps");

    if (maps_file.is_open()) {

        std::string line;
        while (std::getline(maps_file, line)) {

            sscanf(line.c_str(), "%lx-%lx %s", &start, &end, permission);
            //如果可执行
            if (permission[2] == 'x') {

                size_t region_size = end - start;
                char* buffer = new char[region_size];

                // 使用 /proc/self/mem 读取内存区域
                std::ifstream mem_file("/proc/self/mem", std::ios::binary);

                if (mem_file.is_open()) {
                    //从start ~ end的内存区域中搜索target_name字符串，如果存在则返回true
                    mem_file.seekg(start);
                    mem_file.read(buffer, region_size);
                    LOGD("%s => search memory: %lx - %lx", TAG, start, end);
                    // 在内存区域中搜索 target_name
                    if (std::search(buffer, buffer + region_size, target_name.begin(), target_name.end()) != buffer + region_size) {

                        delete[] buffer;
                        mem_file.close();
                        maps_file.close();

                        LOGD("%s => Found target string in memory: %s", TAG, target_name.c_str());

                        return true;

                    }

                    mem_file.close();

                }

                delete[] buffer;

            }

        }

        maps_file.close();

    }

    return false;

}

extern "C"
JNIEXPORT void JNICALL
Java_com_gal2xy_fdetector_MainActivity_initDetector(JNIEnv *env, jobject thiz) {

    // 创建线程来检测frida
    pthread_t t;
    pthread_create(&t, nullptr, detectFridaLoop, (void *)nullptr);

}