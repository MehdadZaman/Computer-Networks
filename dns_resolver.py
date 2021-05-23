# Mehdad Zaman
# 112323211
# CSE 310 Spring 2021

# dns message and query libraries
import dns.message
import dns.query

import datetime

# userInput: domain name (string)
# ipAddress: ip Address (string)
# keyString: string of resource record (string)
def traverseConnection(userInput, ipAddress, keyString):
    # Filters out the IPV6 addresses
    if 'AAAA' in keyString:
        return None

    # Makes the query and sends the UDP connection
    query = dns.message.make_query(userInput, dns.rdatatype.A)
    answers = dns.query.udp(query, ipAddress)

    # Checks response to see if there is an answer
    if len(answers.answer) > 0:
        for key in answers.answer:
            # This is further CNAME resolution (Bonus Part)
            if 'CNAME' in str(key):
                wordArray = str(key).split()
                # Recursively resolve for the CNAME in the answer section
                retValue = traverseConnection(wordArray[len(wordArray) - 1], '198.41.0.4', str(key))
                # return answer
                if retValue:
                    answerArray = [key]
                    answerArray.extend(retValue[0])
                    return answerArray, retValue[1]
            else:
                # return answer
                return [key], key

    # if nothing further to check, just return
    if (len(answers.additional) == 0) and (len(answers.authority) == 0):
        return None

    ipAddresses = []
    keyStrings = []
    domainNames = set()

    # parse additional section resource records for ip addresses
    for key in answers.additional:
        wordArray = str(key).split()
        ipAddresses.append(wordArray[len(wordArray) - 1])
        keyStrings.append(str(key))
        domainNames.add(wordArray[0])

    # resolve query recursively
    i = 0
    for address in ipAddresses:
        retValue = traverseConnection(userInput, address, keyStrings[i])
        if retValue:
            return retValue
        i += 1

    # resolve query recursively in authority section
    for key in answers.authority:
        for item in key.items:
            if (str(item) not in domainNames) and (str(item) != userInput):
                # if no associated ip address for authority server, resolve ip address for NS record
                retValue = traverseConnection(str(item), '198.41.0.4', str(item))
                if retValue:
                    wordArray = str(retValue[1]).split()
                    # continue resolving recursively
                    subRetValue = traverseConnection(userInput, wordArray[len(wordArray) - 1], str(item))
                    if subRetValue:
                        return subRetValue

    return None


if __name__ == "__main__":
    date = datetime.datetime.now()
    cmdLineInput = input()
    args = cmdLineInput.split()

    # argument validation
    while (len(args) != 2) or (args[0] != 'mydig'):
        print('Wrong input')
        print('Usage: \"mydig <domain_name>\"')
        cmdLineInput = input()
        args = cmdLineInput.split()

    time1 = datetime.datetime.now()

    userInput = args[1]
    # Makes the query and sends the UDP connection
    query = dns.message.make_query(userInput, dns.rdatatype.A)
    answers = dns.query.udp(query, '198.41.0.4')

    ipAddresses = []
    keyStrings = []
    finalAnswer = ''

    # parse additional section resource records for ip addresses
    for key in answers.additional:
        wordArray = str(key).split()
        ipAddresses.append(wordArray[len(wordArray) - 1])
        keyStrings.append(str(key))

    # resolve query recursively
    i = 0
    for address in ipAddresses:
        retValue = traverseConnection(userInput, address, keyStrings[i])
        if retValue:
            finalAnswer = retValue
            break
        i += 1

    time2 = datetime.datetime.now()

    # print out values and results
    print('QUESTION SECTION: ')
    print(userInput + '.    IN A\n')

    print('ANSWER SECTION: ')
    if finalAnswer and (finalAnswer != ''):
        for answer in finalAnswer[0]:
            print(answer)

    elapsedTime = time2 - time1
    print('\nQuery Time: ' + str((elapsedTime.microseconds / 1000)) + ' milliseconds')
    print('\nWHEN: ' + str(date))
