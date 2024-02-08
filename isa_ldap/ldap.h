//
// Created by stepan on 27.9.23.
//

#ifndef ISA_LDAP_LDAP_H
#define ISA_LDAP_LDAP_H

#include <string>
#include <getopt.h>
#include <set>

/**
 * @brief structure for storing arguments from command line
 * @param port port to listen on initially set to default 389
 * @param pathToFile path to file with attributes
 */
struct Args {
    int port = 389;
    std::string pathToFile;
};

/**
 * @brief function for parsing ldap protocol, calls the needed ldap functions, called in each thread
 * @param fileContent content of csv file
 * @param packet packet we want to parse
 */
void ldapProtocol(std::set<std::vector<std::string>> fileContent, int packet);

/**
 * @brief structure for storing arguments from command line
 * @param port port to listen on initially set to default 389
 * @param pathToFile path to file with attributes
 */
struct option longOptions[] = {
        {"port", required_argument, nullptr, 'p'},
        {"file", required_argument, nullptr, 'f'},
        {nullptr, 0, nullptr, 0}
};

#endif //ISA_LDAP_LDAP_H
