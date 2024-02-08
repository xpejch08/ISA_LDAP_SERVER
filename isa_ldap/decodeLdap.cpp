//
// Created by stepan on 3.10.23.
//
#include <iostream>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
#include "cmath"
#include "decodeLdap.h"



/**
 * @brief function that returns the id of an ldap message in big endian format
 * @return
 */
int decodeLdapFunctions::getIDOfMessage() {
    //when called the first time, the first byte is already read
    int tmpByte = messageByte;
    int idOfMessage = 0;
    //the id should be 1-4 bytes long
    if(tmpByte < 1 || tmpByte > 4) {
        return -1;
    }
    getNextChar();
    //bit shifting to ensure big endian format
    for (int idIterator = 0; idIterator < tmpByte; ++idIterator) {
        //bitwise and to ensure that only the last 8 bits are used so that we avoid sign extension
        idOfMessage |= (messageByte & 0xFF) << (8 * (tmpByte - 1 - idIterator));
        getNextChar();
    }

    return idOfMessage;
}

/**
 * @brief function that returns the actual message from ldap data
 * @return
 */
std::string decodeLdapFunctions::getMessage() {
    int len = getLenOfMessage(); // Get the length
    std::stringstream actualMessageStream;

    // Loop through the message and add it to the stringstream
    for (int i = 0; i < len; ++i) {
        actualMessageStream << messageByte;
        getNextChar();
    }

    return actualMessageStream.str(); // Convert the stringstream to string and return
}


/**
 * @brief function that returns the length of the ldap message
 * @return
 */
int decodeLdapFunctions::getLenOfMessage() {
    int tmpByte = messageByte;
    int len = 0;

    //checking if we aren't at the end of the message
    if(tmpByte || position != byteSequence.len + 1){
        getNextChar();
    } else {
        position++;
    }
    if(tmpByte < 0x81){
        return tmpByte;
    }

    // If the length is represented in multiple bytes
    int lengthBytesCount = tmpByte & 0x7F; // Mask off the high bit to get the count of bytes

    for (int i = 0; i < lengthBytesCount; ++i) {
        getNextChar();
        len = (len << 8) | messageByte; // Shift len left by 8 bits and OR with the next byte
    }

    return len;
}


/**
 * @brief function that gets the next byte from the LDAP message
 */
void decodeLdapFunctions::getNextChar() {
    read(file, &messageByte, 1);
    position++;
}

/**
 * @brief function that converts a char to string
 * @param character the character we want to convert
 * @return the character but in a string
 */
std::string decodeLdapFunctions::charToString(unsigned char character) {
    std::string ret(1, character);
    return ret;
}

/**
 * @brief function that takes a message and ads its id in front of it in a byte in hexa format
 * @param id the id we want to add to the message
 * @return string containing message with appended ID to the front
 */
std::string decodeLdapFunctions::generateMessageWithID(int id) {
    std::string message = "";

    // Count the number of bytes required to represent the ID
    int bytesRequired = 0;
    int tempId = id;
    while (tempId > 0) {
        tempId >>= 8;
        bytesRequired++;
    }

    // Append the number of bytes as the first byte of the message
    message += static_cast<unsigned char>(bytesRequired);

    // Append the ID in big-endian order
    for (int i = bytesRequired - 1; i >= 0; --i) {
        unsigned char bytePart = (id >> (i * 8)) & 0xFF;
        message += bytePart;
    }

    return message;
}


/**
 * @brief function that takes a message and ads it length in front of it in a byte in hexa format
 * @param inputMessage message we want to add the length byte/s to
 * @return message with length byte/s
 */
std::string decodeLdapFunctions::generateMessageWithLength(std::string inputMessage) {
    std::string message = "";
    unsigned int length = inputMessage.length();

    if (length < 0x81) {
        // Length fits in one byte
        message += static_cast<unsigned char>(length);
    } else {
        // Length requires multiple bytes
        // Determine the number of bytes needed to represent the length
        int lengthBytes = 0;
        unsigned int tempLength = length;
        while (tempLength > 0) {
            tempLength >>= 8;
            lengthBytes++;
        }

        // First byte of the length field is 0x80 + number of additional bytes
        message += static_cast<unsigned char>(0x80 + lengthBytes);

        // Append the length in big-endian format
        for (int i = lengthBytes - 1; i >= 0; --i) {
            unsigned char bytePart = (length >> (i * 8)) & 0xFF;
            message += bytePart;
        }
    }

    // Append the actual message
    message += inputMessage;

    return message;
}