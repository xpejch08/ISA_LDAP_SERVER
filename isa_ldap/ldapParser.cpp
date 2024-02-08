//
// Created by stepan on 16.10.23.
//

#include "decodeLdap.h"
#include <bitset>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <regex>
#include <math.h>
#include <set>


/**
 * @brief constructor for decodeLdapFunctions class
 * @param attributes the parsed attributes from the csv file
 * @param file the file descriptor for writing to, the return from the accept function
 */
decodeLdapFunctions::decodeLdapFunctions(std::set<std::vector<std::string>> attributes, int file) {
    this->file = file;
    this->filterAttributes = attributes;
    decodeLdapFunctions::reset();
}

/**
 * @brief function for the beginning of the parsing process of the ldap message
 */
int decodeLdapFunctions::parseBegin(){
    decodeLdapFunctions::reset();
    decodeLdapFunctions::getNextChar();
    //sequence type
    if(messageByte != 0x30){
        return 0;
    }
    decodeLdapFunctions::getNextChar();
    //getting length of message
    byteSequence.len = decodeLdapFunctions::getLenOfMessage();
    //integer type
    if(messageByte != 0x02){
        return 0;
    }
    decodeLdapFunctions::getNextChar();
    //get id of message
    byteSequence.id = decodeLdapFunctions::getIDOfMessage();

    if(byteSequence.id < 0){
        return 0;
    }
    byteSequence.typeOfMessage = messageByte;

    if(byteSequence.typeOfMessage == BINDREQ){
        return decodeLdapFunctions::bindReq();
    }
    else if(byteSequence.typeOfMessage == SEARCHREQ){
        return decodeLdapFunctions::searchReq();
    }
    else if(byteSequence.typeOfMessage == UNBINDREQ){
        return false;
    }
    else{
        return 0;
    }
}

/**
 * @brief function that processes the bindrequest
 * @return
 */
int decodeLdapFunctions::bindReq() {
    decodeLdapFunctions::getNextChar();
    decodeLdapFunctions::getLenOfMessage();
    //integer type
    if (messageByte != 0x02) {
        return 0;
    }
    decodeLdapFunctions::getNextChar();
    //onebyte integer
    if (messageByte != 0x01) {
        return 0;
    }
    decodeLdapFunctions::getNextChar();
    decodeLdapFunctions::getNextChar();

    //octet string
    if (messageByte != 0x04) {
        return 0;
    }


    decodeLdapFunctions::getNextChar();
    //getting the actual message
    std::string DN = decodeLdapFunctions::getMessage();
    //simple auth
    if (messageByte != 0x80) {
        return 0;
    }
    decodeLdapFunctions::getNextChar();
    std::string simpleAuth = decodeLdapFunctions::getMessage();

    //if we reached the end process bind response
    if (position == byteSequence.len + 2) {
        decodeLdapFunctions::bindRes();
        return 1;
    }
    decodeLdapFunctions::getNextChar();
    //if there are additional components - sasl authentication process the bind response
    if (messageByte == 0xA0 && position == byteSequence.len + 2) {
        decodeLdapFunctions::bindRes();
        return 1;
    }
    return 0;

}


/**
 * @brief function that processes the search request
 * @return
 */
int decodeLdapFunctions::searchReq() {
    decodeLdapFunctions::getNextChar();
    byteSequence.len = decodeLdapFunctions::getLenOfMessage();

    //octet string
    if(messageByte != 0x04){
        return 0;
    }

    decodeLdapFunctions::getNextChar();
    std::string search = decodeLdapFunctions::getMessage();

    //ennumeration type
    if(messageByte != 0x0A){
        return 0;
    }

    //single byte length for scope
    decodeLdapFunctions::getNextChar();
    if(messageByte != 0x01){
        return 0;
    }

    decodeLdapFunctions::getNextChar();
    //check if the scope is a valid scope integer
    if(messageByte > 2){
        return 0;
    }

    decodeLdapFunctions::getNextChar();
    //enumeration type
    if(messageByte != 0x0A){
        return 0;
    }
    decodeLdapFunctions::getNextChar();

    //expecting dereferencing policy in one byte
    if(messageByte != 0x01){
        return 0;
    }

    decodeLdapFunctions::getNextChar();
    //check if dereferencing policy is valid int
    if(messageByte > 3){
        return 0;
    }

    decodeLdapFunctions::getNextChar();
    //integer type - should be size limit after
    if(messageByte != 0x02){
        return 0;
    }

    //getting size limit
    decodeLdapFunctions::getNextChar();
    byteSequence.maxResults = decodeLdapFunctions::getIDOfMessage();

    //another integer
    if(messageByte != 0x02){
        return 0;
    }

    //should be time limit
    decodeLdapFunctions::getNextChar();
    byteSequence.maxTime = decodeLdapFunctions::getIDOfMessage();

    //boolean type
    if(messageByte != 0x01){
        return 0;
    }

    decodeLdapFunctions::getNextChar();
    if(messageByte != 0x01){
        return 0;
    }


    decodeLdapFunctions::getNextChar();
    decodeLdapFunctions::getNextChar();

    //getting the filter
    decodeLdapFunctions::filter = decodeLdapFunctions::LDAPFilterGetter();

    //filter type should be set to one of my constants
    if(filter.filterType == -1){
        return 0;
    }

    //filter through the data, then create search result and search result done message
    out = decodeLdapFunctions::filterLogic(filter);
    decodeLdapFunctions::searchResultGen();
    decodeLdapFunctions::searchResDone();
    return 1;
}


/**
 * @brief function that creates the bind response
 * @return
 */
int decodeLdapFunctions::bindRes() {
    // Construct the innermost part of the response
    std::string innerResponse = {0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};

    // Generate the complete response message
    std::string bindResponse;
    bindResponse.reserve(100); // Reserve enough space to avoid multiple allocations

    // Construct the bindResponse by concatenating different parts
    bindResponse += charToString(0x30); // Start with 0x30 sequence
    bindResponse += generateMessageWithLength(
            charToString(0x02) + //next will be integer
            generateMessageWithID(byteSequence.id) +
            charToString(BINDRES) + //message type bing response
            generateMessageWithLength(innerResponse)
    );

    // Write the response to the packet
    write(file, bindResponse.c_str(), bindResponse.length());
    return 1;
}


/**
 * @brief function that generates the result
 */
void decodeLdapFunctions::searchResultGen() {
    //predefined response attributes
    std::vector <std::string> response = {"cn", "uid", "mail"};

    //iterating over the attributes and generating the response
    for(std::vector<std::string> i : out){
        int iteration = 0;
        std::string result = "";
        //building the response for each attribute
        while(iteration < 3){
            //encoding the attribute cn, uid or mail
            std::string tmp = charToString(0x04) + generateMessageWithLength(i[iteration]);
            //wrapping in a sequence
            tmp = charToString(0x31) + generateMessageWithLength(tmp);
            //enoding the attr name and appending with the value
            std::string secondPart = charToString(0x04) + generateMessageWithLength(response[iteration]);
            result += charToString(0x30) + generateMessageWithLength(secondPart + tmp);
            iteration++;
        }
        //wrapping all combined attributes in a sequence
        result = charToString(0x30) + generateMessageWithLength(result);
        //uid part
        std::string uid = "uid=" + i[1];
        uid = charToString(0x04) + generateMessageWithLength(uid);
        //search res entry encoding
        result = charToString(SEARCHRESENTRY) + generateMessageWithLength(uid + result);

        //adding the id
        result = charToString(0x02) + generateMessageWithID(byteSequence.id) + result;

        //wrapping entire message in a sequence
        result = charToString(0x30) + generateMessageWithLength(result);

        //writing out to our stored socket
        write(file, result.c_str(), result.length());

        //decreasing max results, if we pass the limit the loop breaks
        byteSequence.maxResults--;
        if(byteSequence.maxResults == 0){
            break;
        }
    }
}

/**
 * @brief function that generates the searchres message
 */
void decodeLdapFunctions::searchResDone() {
    // Construct the innermost part of the response
    std::string innerResponse = {0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00};

    // Generate the complete search result done message
    std::string searchResDone;
    searchResDone.reserve(100); // Reserve enough space to avoid multiple allocations

    // Construct the searchResDone by concatenating different parts
    searchResDone += charToString(0x30); // Start with 0x30 sequence
    searchResDone += generateMessageWithLength(
            charToString(0x02) + // Next will be integer (message ID)
            generateMessageWithID(byteSequence.id) +
            charToString(SEARCHRESDONE) + // Message type search result done
            generateMessageWithLength(innerResponse)
    );

    // Write the response to the file
    write(file, searchResDone.c_str(), searchResDone.length());
}

/**
 * @brief a getter function for the ldap filter
 * @return
 */
LDAPFilter decodeLdapFunctions::LDAPFilterGetter() {
    LDAPFilter myFilter;

    //assign the filter type
    myFilter.filterType = messageByte;
    getNextChar();

    //get the length of the filter
    myFilter.lenOfFilter = getLenOfMessage();

    //switch for checking what filter we have and calling handling functions
    if (myFilter.filterType == SUBSTRING || myFilter.filterType == EQUALITY) {
        processEqualityOrSubstringFilter(myFilter);
    } else {
        processNestedFilters(myFilter);
    }

    return myFilter;
}

/**
 * @bried function that processes the equality or substring filter
 * @param filter filter to process
 */
void decodeLdapFunctions::processEqualityOrSubstringFilter(LDAPFilter& filter) {

    //octet string
    if (messageByte != 0x04) {
        filter.filterType = -1;
        return;
    }
    getNextChar();
    //getting the attribute
    filter.attribute = getMessage();

    //converting to lower case because it should be case-insensitive
    std::transform(filter.attribute.begin(), filter.attribute.end(), filter.attribute.begin(), ::tolower);

    //get the index in the map defined in the structure
    filter.attributeIndex = filter.attributeConst[filter.attribute];

    //process substring filter accordingly
    if (filter.filterType == SUBSTRING) {
        processSubstringFilter(filter);
    }
    //process equality filter accordingly
    else if (filter.filterType == EQUALITY) {
        getNextChar();
        filter.attrValue = getMessage();
    }
}

/**
 * @brief dubstring filter handling
 * @param filter filter to process
 */
void decodeLdapFunctions::processSubstringFilter(LDAPFilter& filter) {
    //sequence type
    if (messageByte != 0x30) {
        filter.filterType = -1;
        return;
    }
    //get len of message
    getNextChar();
    int lengthOfMessage = getLenOfMessage();
    //process each part of the filter
    while (lengthOfMessage > 0) {
        unsigned char byte = messageByte;
        getNextChar();
        std::string filterValue = getMessage();
        //append the substring filter part to the filter
        appendSubstringFilter(filter, byte, filterValue);
        //update the remaining len
        lengthOfMessage -= 2 + filterValue.length();
    }
}

/**
 * @brief function that appends the substring filter to the filter
 * @param filter
 * @param byte what filter type we have
 * @param value string of what to append
 */
void decodeLdapFunctions::appendSubstringFilter(LDAPFilter& filter, unsigned char byte, const std::string& value) {
    //depending on the filter value we append different parts of the filter
    switch (byte) {
        case 0x80: filter.attrValue += value + ".*"; break; //append initial part
        case 0x81: filter.attrValue += ".*" + value + ".*"; break; //append any part
        case 0x82: filter.attrValue += ".*" + value; break; //append final part
        default: filter.filterType = -1; //invalid filter
    }
}

/**
 * @brief function to process nested filters
 * @param filter
 */
void decodeLdapFunctions::processNestedFilters(LDAPFilter& filter) {
    //get the len
    int length = filter.lenOfFilter;

    //process each nested filter
    while (length > 0) {
        //get the nested filter
        LDAPFilter nestedFilter = LDAPFilterGetter();

        //append it to the nestedFilter vector
        filter.nestedFilters.push_back(nestedFilter);

        //update the remaining len
        length -= 2 + nestedFilter.lenOfFilter;
    }
}

/**
 * @brief main filter function that handles all the filters and creates the output
 * @param myFilter filter to process and stores all other filters
 * @return output of filtered entries
 */
std::set<std::vector<std::string>> decodeLdapFunctions::filterLogic( LDAPFilter myFilter) {
    std::set<std::vector<std::string>> out;

    //processing the equality or substr filter
    if (myFilter.filterType == EQUALITY || myFilter.filterType == SUBSTRING) {
        std::string regexPattern;

        // Construct the regex pattern based on the filter type
        if (myFilter.filterType == EQUALITY) {
            regexPattern = "^" + myFilter.attrValue + "$"; // Exact match
        } else if (myFilter.filterType == SUBSTRING) {
            regexPattern = myFilter.attrValue; //Substring pattern
            if (regexPattern[0] == '*') {
                //leading asterisk for substring match
                regexPattern.erase(0, 1); // Remove leading asterisk for substring matching
            } else {
                regexPattern = "^" + regexPattern; // Anchor at the beginning
            }
            if (regexPattern.back() == '*') {
                regexPattern.pop_back(); // Remove trailing asterisk
            } else {
                regexPattern += "$"; // Anchor at the end
            }
        }

        //iterate through the filter attributes to find matches
        for (const auto& iterator : filterAttributes) {
            //iterate through nested filters and combine their resultr
            if (std::regex_search(iterator[myFilter.attributeIndex], std::regex(regexPattern, std::regex::ECMAScript | std::regex::icase))) {
                out.insert(iterator);
            }
        }
    }
    //or filter
    if(myFilter.filterType == OR){
        //iterate through nested filters and combine their results
        for(LDAPFilter iterator : myFilter.nestedFilters){
            std::set<std::vector<std::string>> nested = filterLogic(iterator);
            out.insert(nested.begin(), nested.end());
        }
    }
    //and filter
    if(myFilter.filterType == AND){
        //start with the results of the first nested filter
        out = filterLogic(myFilter.nestedFilters[0]);
        for(LDAPFilter iterator : myFilter.nestedFilters){
            std::set<std::vector<std::string>> nested = filterLogic(iterator);
            std::set<std::vector<std::string>> nested2 = out;
            out.clear();
            //performing the intersection to get common elements
            std::set_intersection(nested2.begin(), nested2.end(), nested.begin(), nested.end(), std::inserter(out, out.begin()));
        }
    }
    //not filter
    if(myFilter.filterType == NOT){
        //combine results of the nested filters
        std::set<std::vector<std::string>> nested = filterLogic(myFilter.nestedFilters[0]);
        //iterate through the filter attributes and find the ones that are not in the result, add them to the output
        for(std::vector<std::string> iterator : filterAttributes){
            if(nested.find(iterator) == nested.end()){
                out.emplace(iterator);
            }
        }
    }
    return out; //returning the output
}

/**
 * @brief function to reset the variables for reading through the message
 */
void decodeLdapFunctions::reset() {
    this->position = -1;
    this->messageByte = -1;
}

