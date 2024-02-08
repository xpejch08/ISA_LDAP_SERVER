//
// Created by stepan on 13.10.23.
//

#ifndef ISA_LDAP_DECODELDAP_H
#define ISA_LDAP_DECODELDAP_H

#include <string>
#include <vector>
#include <map>
#include <set>

//filter constants
const int AND = 0xA0;
const int SUBSTRING = 0xA4;
const int EQUALITY = 0xA3;
const int OR = 0xA1;
const int NOT = 0xA2;

//request constants
const int BINDREQ = 0x60;
const int BINDRES = 0x61;
const int SEARCHREQ = 0x63;
const int SEARCHRESENTRY = 0x64;
const int SEARCHRESDONE = 0x65;
const int UNBINDREQ = 0x42;

/**
 * @brief LDAPFilter class for storing filter information
 * @param lenOfFilter length of filter
 * @param attributeIndex index of attribute in filter
 * @param filterType type of filter defined by filter constants
 * @param attrValue value of attribute
 * @param attribute name of attribute
 * @param nestedFilters vector of nested filters
 * @param attributeConst map for converting attribute name to index
 */
class LDAPFilter{
public:
    int lenOfFilter = 0, attributeIndex, filterType = -1;
    std::string attrValue;
    std::string attribute;
    std::vector <LDAPFilter> nestedFilters;
    std::map<std::string, int> attributeConst =
                              {{"cn", 0}, {"commonname", 0},
                              {"uid", 1}, {"userid", 1},
                              {"mail", 2}};
};

/**
 * @brief LDAPMessage class for storing message information
 * @param id id of message
 * @param len length of message
 * @param maxResults maximum number of results to return
 * @param maxTime maximum time to wait for results, used just for assigning
 * @param typeOfMessage type of message defined by request constants
 * @param message actual message
 */
class LDAPMessage{
public:
    int id;
    int len;
    int maxResults;
    int maxTime;
    int typeOfMessage;
    std::string message;
};

/**
 * @brief class for decoding ldap protocol
 * @param byteSequence structure for storing message information
 * @param filterAttributes set of attributes from csv file
 * @param out set of attributes that will be returned
 * @param messageByte current byte of message
 * @param file file descriptor for writing to, stors the return of the accept function
 * @param position position in message
 * @param filter structure for storing filter information
 */
class decodeLdapFunctions{
public:
    decodeLdapFunctions(std::set<std::vector<std::string>> attributes, int file);
    int parseBegin();

private:
    LDAPMessage byteSequence;
    std::set<std::vector<std::string>> filterAttributes;
    std::set<std::vector<std::string>> out;
    unsigned char messageByte;
    int file;
    int position;
    LDAPFilter filter;

    void reset();
    int getLenOfMessage();
    int getIDOfMessage();
    std::string getMessage();
    std::string charToString(unsigned char ch);
    std::string generateMessageWithLength(std::string message);
    std::string generateMessageWithID(int id);
    void getNextChar();
    LDAPFilter LDAPFilterGetter();
    std::set<std::vector<std::string>> filterLogic(LDAPFilter myFilter);
    int bindReq();
    int searchReq();
    int bindRes();
    void searchResultGen();
    void searchResDone();

    void processEqualityOrSubstringFilter(LDAPFilter &filter);

    void processSubstringFilter(LDAPFilter &filter);

    void appendSubstringFilter(LDAPFilter &filter, unsigned char byte, const std::string &value);

    void processNestedFilters(LDAPFilter &filter);
};

#endif //ISA_LDAP_DECODELDAP_H
