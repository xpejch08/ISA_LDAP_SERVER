#include <iostream>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <bitset>
#include <sys/socket.h>
#include <sys/types.h>
#include <iomanip>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <vector>
#include <fcntl.h>
#include <fstream>
#include "ldap.h"
#include "decodeLdap.h"
//#include <thread>
#include <signal.h>

#define BUFFER_SIZE 1024

class helpFunctions{
public:
    /**
     * @brief function for checking arguments
     * @param argc
     * @param argv
     * @param arguments actual arguments from command line
     * @return 0 if arguments are ok, 1 if not
     */
    int argumentsCheck(int argc, char* argv[], Args *arguments){
        int getOptRet;
        while((getOptRet = getopt_long(argc, argv, "p:f:", longOptions, nullptr)) != -1){
            switch (getOptRet) {
                case 'p':
                    arguments->port = std::stoi(optarg);
                    break;
                case 'f':
                    arguments->pathToFile = optarg;
                    break;
                default:
                    return 1;
            }
        }
        return 0;

    }
};

class server {
public:
    Args arguments;

    /**
     * @brief function for creating socket
     */
    void createSocket(){
        if ((cSocket = socket(AF_INET, SOCK_STREAM, 0)) <= 0)
        {
            std::cerr << "ERROR: problem with creating socket" << std::endl;
            exit(EXIT_FAILURE);
        }
        bzero(&serverAdress, sizeof(serverAdress));
    }

    /**
     * @brief function for assigning address
     */
    void assignAddres(){
        serverAdress.sin_family = AF_INET;
        serverAdress.sin_addr.s_addr = htonl(INADDR_ANY);
        serverAdress.sin_port = htons(arguments.port);
    }

    /**
     * @brief function for binding socket
     */
    void bindSocket(){
        //setting cSocket to be reusable, so we can run server again without waiting for timeout
        int opt = 1;
        if (setsockopt(cSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            std::cerr << "ERROR: setsockopt failed" << std::endl;
            exit(EXIT_FAILURE);
        }
        if((bind(cSocket, (sockaddr*)&serverAdress, sizeof(serverAdress))) != 0){
            std::cerr << "ERROR: problem with binding" << std::endl;
            exit(EXIT_FAILURE);
        }
        else{
            std::cout << "Binded" << std::endl;
        }
    }

    /**
     * @brief function for listening on socket
     */
    void listenS(){
        if((listen(cSocket, 5)) != 0){
            std::cerr << "ERROR: listen error" << std::endl;
            exit(EXIT_FAILURE);
        }
        length = sizeof(client);

        //reading csv file specified in the arguments
        std::ifstream fileParameter(arguments.pathToFile);
        if(!fileParameter.is_open()){
            exit(EXIT_FAILURE);
        }
        //reading csv file line by line and inserting it into set
        std::string seperateLine;
        while(std::getline(fileParameter, seperateLine)){
            std::vector<std::string> parts;
            std::stringstream ss(seperateLine);
            std::string item;

            //splitting each line by a semicolon and storing it in 'parts'
            while (std::getline(ss, item, ';')) {
                //pushing the item into vector
                parts.push_back(removeWhitespace(item));
            }

            //inserting into set of vectors of strings
            fileContent.insert(parts);
        }
    }

    /**
     * @brief function for reading packets and multithread adding
     */
    void readPacket() {
        while (true) {
            packet = accept(cSocket, NULL, NULL);
            if (packet == -1) {
                std::cerr << "ERROR: accept failed" << std::endl;
                exit(EXIT_FAILURE);
            } else {
                std::cout << "Accept ok" << std::endl;
            }

            pid_t pid = fork();  // Create a new process

            if (pid == -1) {
                // If fork() returns -1, an error occurred
                std::cerr << "ERROR: fork failed" << std::endl;
                close(packet);
            } else if (pid == 0) {
                // Child process
                close(cSocket);  // Close the listening socket in the child process
                ldapProtocol(fileContent, packet);  // Process the request
                close(packet);  // Close the connected socket
                exit(0);  // Exit the child process
            } else {
                // Parent process
                close(packet);  // Close the connected socket in the parent process
            }
        }
    }


    /**
     * @brief function for removing whitespace from string
     * @param string the string we want to return the whitespaces from
     * @return string without white spaces
     */
    std::string removeWhitespace(std::string string){
        // Find the first non-whitespace character from the beginning
        auto start = string.find_first_not_of(" \t\n\r\f\v");

        // If no non-whitespace characters found, the string is empty or contains only whitespace
        if (start == std::string::npos) {
            return "";
        }

        // Find the last non-whitespace character from the end
        auto end = string.find_last_not_of(" \t\n\r\f\v");

        // Extract the trimmed substring
        return string.substr(start, end - start + 1);
    }

    /**
     * @brief function for closing socket
     */
    void closeSocket(){
        close(cSocket);
        close(packet);
    }



private:
    int cSocket, packet, length, parsingIterator = 0;
    int first = 0;
    struct sockaddr_in serverAdress, client;
    unsigned char buffer[BUFFER_SIZE];
    std::string request;
    std::set<std::vector<std::string>> fileContent; //container for csv file
public:

};

/**
 * @brief function for parsing ldap protocol, calls the needed ldap functions, called in each thread
 * @param fileContent content of csv file
 * @param packet packet we want to parse
 */
void ldapProtocol(std::set<std::vector<std::string>> fileContent, int packet) {
    decodeLdapFunctions LDAPProtocol(fileContent, packet);
    while(LDAPProtocol.parseBegin());
    close(packet);
}

//global variable for signal handler, so we can close the correct sockets
server *globalServerPointerForSigint;

/**
 * @brief signal handler for SIGINT, closes all sockets and exits program
 * @param signum signal for catching
 */
void signal_callback_handler(int signum){
    globalServerPointerForSigint->closeSocket();
    printf("Got signal SIGINT releasing sockets and exiting.\n");
    exit(signum);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_callback_handler);
    Args arguments;
    helpFunctions help;
    server serverO;
    //setting global var for sigint handling
    globalServerPointerForSigint = &serverO;

    if(help.argumentsCheck(argc, argv, &arguments) == 1){
        return 1;
    }


    serverO.arguments.port = arguments.port;
    serverO.arguments.pathToFile = arguments.pathToFile;

    std::cout << arguments.port << " " << arguments.pathToFile;

    serverO.createSocket();
    serverO.assignAddres();
    serverO.bindSocket();
    serverO.listenS();
    serverO.readPacket();

    return 0;
}