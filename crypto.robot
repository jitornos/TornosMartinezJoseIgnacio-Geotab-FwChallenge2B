*** Settings ***
Documentation     Crytography algorithm verfication
Library           Process

*** Variables ***
${VERSION}        01.00.00
${KEYSTRING}      KEYSTRING
${KEYFILE}        keyfile
${KEYSIZE}        200
${INPUTFILE}      inputfile
${INPUTSIZE}      32768
${OUTPUTFILE1}    outputfile1
${OUTPUTFILE2}    outputfile2

*** Test Cases ***
Version Test
    [Documentation]    Get Cryptography library version and check.
    ${result}    Run Process    ./fw2b       -v
    Should Be Equal As Integers     ${result.rc}    0
    Log    ${result.stdout}
    Should Be Equal    ${VERSION}    ${result.stdout}

Encrypt Message Test (key string)  
    [Documentation]    Encrypt message, key string is used.
    ...    Encrypt again to recover initial message and check.
    [Teardown]    Clean Products
    Random File    ${INPUTFILE}    ${INPUTSIZE}
    Encrypt From File To File With Key String    ${KEYSTRING}    ${INPUTFILE}    ${OUTPUTFILE1}
    ${result}    Run Process    diff    ${OUTPUTFILE1}    ${INPUTFILE}
    Should Be Equal As Integers     ${result.rc}    1
    Encrypt From File To File With Key String    ${KEYSTRING}    ${OUTPUTFILE1}    ${OUTPUTFILE2}
    ${result}    Run Process    diff    ${OUTPUTFILE2}    ${INPUTFILE}
    Should Be Equal As Integers     ${result.rc}    0

Encrypt Message Test (key file)  
    [Documentation]    Encrypt message, key file is used.
    ...    Encrypt again to recover initial message and check.
    [Teardown]    Clean Products
    Random File    ${KEYFILE}    ${KEYSIZE}
    Random File    ${INPUTFILE}    ${INPUTSIZE}
    Encrypt From File To File With Key File    ${KEYFILE}    ${INPUTFILE}    ${OUTPUTFILE1}
    ${result}    Run Process    diff    ${OUTPUTFILE1}    ${INPUTFILE}
    Should Be Equal As Integers     ${result.rc}    1
    Encrypt From File To File With Key File    ${KEYFILE}    ${OUTPUTFILE1}    ${OUTPUTFILE2}
    ${result}    Run Process    diff    ${OUTPUTFILE2}    ${INPUTFILE}
    Should Be Equal As Integers     ${result.rc}    0

Encrypt Message Test (key file and pipes)  
    [Documentation]    Encrypt message, key file and pipes are used.
    ...    Encrypt again to recover initial message and check.
    [Teardown]    Clean Products
    Random File    ${KEYFILE}    ${KEYSIZE}
    Random File    ${INPUTFILE}    ${INPUTSIZE}
    Encrypt From Pipe To Pipe With Key File    ${KEYFILE}    ${INPUTFILE}    ${OUTPUTFILE1}
    ${result}    Run Process    diff    ${OUTPUTFILE1}    ${INPUTFILE}
    Should Be Equal As Integers     ${result.rc}    1
    Encrypt From Pipe To Pipe With Key File    ${KEYFILE}    ${OUTPUTFILE1}    ${OUTPUTFILE2}
    ${result}    Run Process    diff    ${OUTPUTFILE2}    ${INPUTFILE}
    Should Be Equal As Integers     ${result.rc}    0

*** Keywords ***
Random File
    [Documentation]     Generate random file
    [Arguments]         ${filename}    ${size}
    ${result}   Run Process     dd    if\=/dev/urandom    of\=${filename}    bs\=${size}    count\=1    status\=none
    Should Be Equal As Integers     ${result.rc}    0

Encrypt From File To File With Key String
    [Documentation]     Encrypt from file to file using key string
    [Arguments]         ${keystring}    ${inputfile}    ${outputfile}
    ${result}    Run Process    ./fw2b    -k    ${keystring}    -o    ${outputfile}    ${inputfile}
    Should Be Equal As Integers     ${result.rc}    0

Encrypt From File To File With Key File
    [Documentation]     Encrypt from file to file using key in file
    [Arguments]         ${keyfile}    ${inputfile}    ${outputfile}
    ${result}    Run Process    ./fw2b    -f    ${keyfile}    -o    ${outputfile}    ${inputfile}
    Should Be Equal As Integers     ${result.rc}    0

Encrypt From Pipe To Pipe With Key File
    [Documentation]     Encrypt from pipe to pipe using key in file
    [Arguments]         ${keyfile}    ${inputfile}    ${outputfile}
    ${result}    Run Process    cat    ${inputfile}    |    ./fw2b    -f    ${keyfile}    >    ${outputfile}    shell=yes
    Should Be Equal As Integers     ${result.rc}    0

Clean Products
    [Documentation]     Clean generated products
    ${result}    Run Process    rm    -f    ${KEYFILE}    ${INPUTFILE}    ${OUTPUTFILE1}    ${OUTPUTFILE2}
    Should Be Equal As Integers     ${result.rc}    0

