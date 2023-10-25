@echo off
cls
set filename=kms_secure_private
set CAfilename=kms_secure_privateCA
set CRTfilename=kms_secure_privateCRT
set exepath=C:\Strawberry\c\bin\openssl.exe

%exepath% genrsa -out "%filename%.key" 2048
IF NOT EXIST "%filename%.key" (
    ECHO genera failed to produce output
    EXIT /B
    )
	
%exepath% req -new -key %filename%.key -out %filename%.csr
IF NOT EXIST "%filename%.csr" (
    ECHO req failed to produce output
    EXIT /B
    )
	
%exepath% genrsa -aes256 -out %CAfilename%.key 2048


%exepath% req -x509 -new -nodes -key %CAfilename%.key -days 3650 -out %CAfilename%.pem

%exepath% x509 -req -in %filename%.csr -CA %CAfilename%.pem -CAkey %CAfilename%.key -CAcreateserial -out %CRTfilename%.crt -days 365
