# wincrypt
File encryption using WinCrypt API

Windows executable that encrypts a source file with a randomly generated AES-256 key.  The key is encrypted using a PEM-encoded RSA public key.  This can be used for secure archiving.  The RSA private key is needed to recover the encrypted file.

**Example of generating a password-protected RSA key pair**
```
openssl genrsa -out rsakey.key -aes256 4096

(extract the public key, which will be used by the Windows executable)
openssl rsa -in rsakey.key -pubout -out rsakey.pub -outform pem
```

**Windows executable C source**

Source file is `secureblob.c` compile using `i686-w64-mingw32-gcc -mconsole ./secureblob.c -o ./secureblob.exe -lshlwapi -lcrypt32`

```c
/*
   Windows executable that encrypts a source file with a randomly generated
   AES-256 key which is stored within the secure blob using a PEM-encoded
   RSA public key.  This can be used for secure archival.  Use the RSA
   private key to recover the original source file.  The secure blob contains
   four ASCIIZ headers that can be used to decrypt the file.

   (output file structure)
   hdr[0]        = original filename
   hdr[1]        = SHA-256 hash of original file as hex string
   hdr[2]        = SHA-256 hash of public key as hex string
   hdr[3]        = AES-256 key encrypted with public key as hex string
   [binary blob] = encrypted file data

   Program:
   input: an RSA public key PEM file, a source file to encrypt
   output: an encrypted version of the source file with headers

   Example usage:
   secureblob.exe public.pem source.doc \\10.1.2.3\archives\000001.enc

   Compile:
   i686-w64-mingw32-gcc -mconsole ./secureblob.c -o ./secureblob.exe -lshlwapi -lcrypt32
*/

#include <windows.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>

#define PEMBUF 1048576
#define SHA256BYTES 32
#define AES256KEYBYTES 32
#define AESBLOCKBYTES 16
#define BLOCKMULT 256

void Byte2Hex(BYTE *pIn, DWORD dwInLen, char *pOut);
void Etyb2Hex(BYTE *pIn, DWORD dwInLen, char *pOut);

int main(int argc, char **argv)
{
   char *pPemFile, *pInFile, *pOutFile, *pInFileName;
   BYTE *pPemBuf, *pPubKey, *pPubKeySHA256, *pAESKey, *pAESKeyEnc, *pReadBuf, *pFileSHA256;
   DWORD dwPemSize, dwTemp, dwDiff, dwAESLen;
   HANDLE hRead, hWrite;
   CERT_PUBLIC_KEY_INFO *pPubKeyInfo;
   HCRYPTPROV hProv = 0;
   HCRYPTKEY hPubKey = 0, hAESKey = 0;
   HCRYPTHASH hFileSHA256;
   char szSHA256Hex[(SHA256BYTES * 2) + 1];
   char szAESKeyHex[(AES256KEYBYTES * 2) + 1];
   char szFileSHA256Hex[(SHA256BYTES * 2) + 1];
   char *pAESKeyEncHex;
   char szBlank[] = "0000000000000000000000000000000000000000000000000000000000000000";
   BOOL bEOF = FALSE;

   if(argc != 4)
   {
      fprintf(stderr, "You must provide 3 parameters:\n<public key pem file> <input file> <output file>\n");
      return -1;
   }
   if(!strcmp(argv[2], argv[3]))
   {
      fprintf(stderr, "The output file cannot be the same as the input file.\n");
      return -1;
   }
   pPemFile = argv[1];
   pInFile = argv[2];
   pOutFile = argv[3];
   if((hRead = CreateFile(pPemFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL)) == INVALID_HANDLE_VALUE)
   {
      fprintf(stderr, "Error opening PEM file, %d\n", GetLastError());
      return -1;
   }
   dwPemSize = GetFileSize(hRead, &dwTemp);
   if(dwPemSize == INVALID_FILE_SIZE || dwPemSize == 0 || dwPemSize >= PEMBUF || dwTemp > 0)
   {
      fprintf(stderr, "Error bad PEM file size, %d, %d\n", GetLastError(), dwPemSize);
      CloseHandle(hRead);
      return -1;
   }
   if(!(pPemBuf = (BYTE *)malloc(PEMBUF)))
   {
      fprintf(stderr, "Error allocating PEM file buffer.\n");
      CloseHandle(hRead);
      return -1;
   }
   memset(pPemBuf, 0, PEMBUF);
   if(!ReadFile(hRead, pPemBuf, dwPemSize, &dwPemSize, NULL))
   {
      fprintf(stderr, "Error reading PEM file, %d\n", GetLastError());
      CloseHandle(hRead);
      free(pPemBuf);
      return -1;
   }
   CloseHandle(hRead);
   dwPemSize = 0;
   if(!CryptStringToBinary(pPemBuf, 0, CRYPT_STRING_BASE64HEADER, NULL, &dwPemSize, NULL, NULL))
   {
      fprintf(stderr, "Error determining PEM buffer size, %d\n", GetLastError());
      free(pPemBuf);
      return -1;
   }
   if(dwPemSize < 1)
   {
      fprintf(stderr, "Error PEM buffer value.\n");
      free(pPemBuf);
      return -1;
   }
   if(!(pPubKey = (BYTE *)malloc(dwPemSize)))
   {
      fprintf(stderr, "Error allocating public key buffer.\n");
      free(pPemBuf);
      return -1;
   }
   if(!CryptStringToBinary(pPemBuf, 0, CRYPT_STRING_BASE64HEADER, pPubKey, &dwPemSize, NULL, NULL))
   {
      fprintf(stderr, "Error retrieving public key, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      return -1;
   }
   if(!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pPubKey, dwPemSize, CRYPT_ENCODE_ALLOC_FLAG, NULL, &pPubKeyInfo, &dwTemp))
   {
      fprintf(stderr, "Error CryptDecodeObjectEx, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      return -1;
   }
   dwTemp = 0;
   if(!CryptHashPublicKeyInfo(0, CALG_SHA_256, 0, X509_ASN_ENCODING, pPubKeyInfo, NULL, &dwTemp))
   {
      fprintf(stderr, "Error CryptHashPublicKeyInfo determine length, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      LocalFree(pPubKeyInfo);
      return -1;
   }
   if(dwTemp != SHA256BYTES)
   {
      fprintf(stderr, "Error public key SHA-256 length.\n");
      free(pPemBuf);
      free(pPubKey);
      LocalFree(pPubKeyInfo);
      return -1;
   }
   if(!(pPubKeySHA256 = (BYTE *)malloc(SHA256BYTES)))
   {
      fprintf(stderr, "Error allocating public key SHA-256 buffer.\n");
      free(pPemBuf);
      free(pPubKey);
      LocalFree(pPubKeyInfo);
      return -1;
   }
   if(!CryptHashPublicKeyInfo(0, CALG_SHA_256, 0, X509_ASN_ENCODING, pPubKeyInfo, pPubKeySHA256, &dwTemp))
   {
      fprintf(stderr, "Error CryptHashPublicKeyInfo, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      LocalFree(pPubKeyInfo);
      return -1;
   }
   if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
   {
      fprintf(stderr, "Error CryptAcquireContext, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      LocalFree(pPubKeyInfo);
      return -1;
   }
   if(!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pPubKeyInfo, &hPubKey))
   {
      fprintf(stderr, "Error CryptImportPublicKeyInfo, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      LocalFree(pPubKeyInfo);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   if(!CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hAESKey))
   {
      fprintf(stderr, "Error CryptGenKey, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   if(!CryptExportKey(hAESKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &dwTemp))
   {
      fprintf(stderr, "Error CryptExportKey determine length, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   if(!(pAESKey = (BYTE *)malloc(dwTemp)))
   {
      fprintf(stderr, "Error allocating AES key buffer.\n");
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   if(!CryptExportKey(hAESKey, 0, PLAINTEXTKEYBLOB, 0, pAESKey, &dwTemp))
   {
      fprintf(stderr, "Error CryptExportKey, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   dwDiff = sizeof(BLOBHEADER) + sizeof(DWORD);
   dwAESLen = dwTemp - dwDiff;
   if(dwAESLen != AES256KEYBYTES)
   {
      fprintf(stderr, "Error CryptExportKey length.\n");
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   Byte2Hex(pPubKeySHA256, SHA256BYTES, szSHA256Hex);
   Byte2Hex(pAESKey + dwDiff, AES256KEYBYTES, szAESKeyHex);
   dwTemp = AES256KEYBYTES;
   if(!CryptEncrypt(hPubKey, 0, TRUE, 0, 0, &dwTemp, 0))
   {
      fprintf(stderr, "Error CryptEncrypt RSA determine length, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   if(!(pAESKeyEnc = (BYTE *)malloc(dwTemp)))
   {
      fprintf(stderr, "Error allocating encrypted key buffer.\n");
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   memcpy(pAESKeyEnc, pAESKey + dwDiff, AES256KEYBYTES);
   if(!CryptEncrypt(hPubKey, 0, TRUE, 0, pAESKeyEnc, &dwAESLen, dwTemp))
   {
      fprintf(stderr, "Error CryptEncrypt RSA, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   if(!(pAESKeyEncHex = (BYTE *)malloc((dwAESLen * 2) + 1)))
   {
      fprintf(stderr, "Error allocating encrypted AES key string buffer.\n");
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   Etyb2Hex(pAESKeyEnc, dwAESLen, pAESKeyEncHex);
   if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hFileSHA256))
   {
      fprintf(stderr, "Error CryptCreateHash, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   pInFileName = PathFindFileName(pInFile);
   if(!strlen(pInFileName))
   {
      fprintf(stderr, "Error source file name length.\n");
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   if((hRead = CreateFile(pInFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL)) == INVALID_HANDLE_VALUE)
   {
      fprintf(stderr, "Error opening source file, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      return -1;
   }
   if(!GetFileSize(hRead, &dwTemp))
   {
      if(dwTemp == 0)
      {
         fprintf(stderr, "Source file is empty, nothing to do.\n");
         free(pPemBuf);
         free(pPubKey);
         free(pPubKeySHA256);
         free(pAESKey);
         free(pAESKeyEnc);
         LocalFree(pPubKeyInfo);
         CryptDestroyKey(hPubKey);
         CryptDestroyKey(hAESKey);
         CryptReleaseContext(hProv, 0);
         return -1;
      }
   }
   if((hWrite = CreateFile(pOutFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
   {
      fprintf(stderr, "Error creating destination file, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      return -1;
   }
   if(!(pReadBuf = (BYTE *)malloc(AESBLOCKBYTES * BLOCKMULT)))
   {
      fprintf(stderr, "Error allocating file buffer.\n");
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   dwTemp = strlen(pInFileName) + 1;
   if(!WriteFile(hWrite, pInFileName, dwTemp, &dwTemp, NULL))
   {
      fprintf(stderr, "Error WriteFile, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   dwTemp = strlen(szBlank) + 1;
   if(!WriteFile(hWrite, szBlank, dwTemp, &dwTemp, NULL))
   {
      fprintf(stderr, "Error WriteFile, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   dwTemp = strlen(szSHA256Hex) + 1;
   if(!WriteFile(hWrite, szSHA256Hex, dwTemp, &dwTemp, NULL))
   {
      fprintf(stderr, "Error WriteFile, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   dwTemp = strlen(pAESKeyEncHex) + 1;
   if(!WriteFile(hWrite, pAESKeyEncHex, dwTemp, &dwTemp, NULL))
   {
      fprintf(stderr, "Error WriteFile, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   while(!bEOF)
   {
      if(!ReadFile(hRead, pReadBuf, (AESBLOCKBYTES * BLOCKMULT), &dwTemp, NULL))
      {
         fprintf(stderr, "Error ReadFile, %d\n", GetLastError());
         free(pPemBuf);
         free(pPubKey);
         free(pPubKeySHA256);
         free(pAESKey);
         free(pAESKeyEnc);
         free(pReadBuf);
         LocalFree(pPubKeyInfo);
         CryptDestroyKey(hPubKey);
         CryptDestroyKey(hAESKey);
         CryptReleaseContext(hProv, 0);
         CloseHandle(hRead);
         CloseHandle(hWrite);
         DeleteFile(pOutFile);
         return -1;
      }
      if(!CryptHashData(hFileSHA256, pReadBuf, dwTemp, 0))
      {
         fprintf(stderr, "Error CryptHashData, %d\n", GetLastError());
         free(pPemBuf);
         free(pPubKey);
         free(pPubKeySHA256);
         free(pAESKey);
         free(pAESKeyEnc);
         free(pReadBuf);
         LocalFree(pPubKeyInfo);
         CryptDestroyKey(hPubKey);
         CryptDestroyKey(hAESKey);
         CryptReleaseContext(hProv, 0);
         CloseHandle(hRead);
         CloseHandle(hWrite);
         DeleteFile(pOutFile);
         return -1;
      }
      if(dwTemp != (AESBLOCKBYTES * BLOCKMULT)) bEOF = TRUE;
      if(!CryptEncrypt(hAESKey, 0, bEOF, 0, pReadBuf, &dwTemp, (AESBLOCKBYTES * BLOCKMULT)))
      {
         fprintf(stderr, "Error CryptEncrypt AES, %d\n", GetLastError());
         free(pPemBuf);
         free(pPubKey);
         free(pPubKeySHA256);
         free(pAESKey);
         free(pAESKeyEnc);
         free(pReadBuf);
         LocalFree(pPubKeyInfo);
         CryptDestroyKey(hPubKey);
         CryptDestroyKey(hAESKey);
         CryptReleaseContext(hProv, 0);
         CloseHandle(hRead);
         CloseHandle(hWrite);
         DeleteFile(pOutFile);
         return -1;
      }
      if(!WriteFile(hWrite, pReadBuf, dwTemp, &dwTemp, NULL))
      {
         fprintf(stderr, "Error WriteFile, %d\n", GetLastError());
         free(pPemBuf);
         free(pPubKey);
         free(pPubKeySHA256);
         free(pAESKey);
         free(pAESKeyEnc);
         free(pReadBuf);
         LocalFree(pPubKeyInfo);
         CryptDestroyKey(hPubKey);
         CryptDestroyKey(hAESKey);
         CryptReleaseContext(hProv, 0);
         CloseHandle(hRead);
         CloseHandle(hWrite);
         DeleteFile(pOutFile);
         return -1;
      }
   }
   if(!(pFileSHA256 = (BYTE *)malloc(SHA256BYTES)))
   {
      fprintf(stderr, "Error allocating file hash buffer.\n");
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   dwTemp = SHA256BYTES;
   if(!CryptGetHashParam(hFileSHA256, HP_HASHVAL, pFileSHA256, &dwTemp, 0))
   {
      fprintf(stderr, "Error CryptGetHashParam, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      free(pFileSHA256);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   if(dwTemp != SHA256BYTES)
   {
      fprintf(stderr, "Error CryptGetHashParam length, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      free(pFileSHA256);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   Byte2Hex(pFileSHA256, dwTemp, szFileSHA256Hex);
   if(SetFilePointer(hWrite, strlen(pInFileName) + 1, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
   {
      fprintf(stderr, "Error SetFilePointer, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      free(pFileSHA256);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }
   dwTemp = SHA256BYTES * 2;
   if(!WriteFile(hWrite, szFileSHA256Hex, dwTemp, &dwTemp, NULL))
   {
      fprintf(stderr, "Error WriteFile, %d\n", GetLastError());
      free(pPemBuf);
      free(pPubKey);
      free(pPubKeySHA256);
      free(pAESKey);
      free(pAESKeyEnc);
      free(pReadBuf);
      free(pFileSHA256);
      LocalFree(pPubKeyInfo);
      CryptDestroyKey(hPubKey);
      CryptDestroyKey(hAESKey);
      CryptReleaseContext(hProv, 0);
      CloseHandle(hRead);
      CloseHandle(hWrite);
      DeleteFile(pOutFile);
      return -1;
   }

   free(pPemBuf);
   free(pPubKey);
   free(pPubKeySHA256);
   free(pAESKey);
   free(pAESKeyEnc);
   free(pReadBuf);
   free(pFileSHA256);
   LocalFree(pPubKeyInfo);
   CryptDestroyKey(hPubKey);
   CryptDestroyKey(hAESKey);
   CryptReleaseContext(hProv, 0);
   CloseHandle(hRead);
   CloseHandle(hWrite);

   return 0;
}

void Byte2Hex(BYTE *pIn, DWORD dwInLen, char *pOut)
{
   DWORD dwTemp;

   for(dwTemp = 0; dwTemp < dwInLen; dwTemp++)
   {
      sprintf(pOut + (dwTemp * 2), "%02x", pIn[dwTemp]);
   }
}

void Etyb2Hex(BYTE *pIn, DWORD dwInLen, char *pOut)
{
   int nTemp;
   char *pChar = pOut;

   for(nTemp = dwInLen - 1; nTemp > -1; nTemp--, pChar += 2)
   {
      sprintf(pChar, "%02x", pIn[nTemp]);
   }
}
```

**Linux bash script to decrypt the file**

Script name `secure_blob_recover.sh`

```bash
#!/usr/bin/bash

read -p 'Enter the file to decrypt: ' infile
read -p 'Enter the private key PEM file: ' keyfile

pubhash=$(openssl rsa -in "$keyfile" -pubout -out - -outform der | sha256sum | cut -d " " -f 1)

headers=( $(strings -n 1 "$infile" 2>/dev/null | head -n 4) )
for i in {1..3}
do
   echo "${headers[$i]}" | egrep '^[0-9a-f]{64,}$' >/dev/null
   if [ $? -ne 0 ]
   then
      echo "Header check failed."
      exit -1
   fi
done

if [ "${headers[2]}" != "$pubhash" ]
then
   echo "Public key fingerprint does not match."
   exit -1
fi

aeskey=$(echo "${headers[3]}" | xxd -r -p | openssl rsautl -decrypt -in - -out - -inkey "$keyfile" | xxd -p -c 256)
skip=$((${#headers[0]}+${#headers[1]}+${#headers[2]}+${#headers[3]}+4))
enctmp=$(mktemp)
dd if=$infile bs=$skip skip=1 >$enctmp 2>/dev/null
cat $enctmp | openssl enc -aes-256-cbc -nosalt -K $aeskey -iv 00000000000000000000000000000000 -d >"/tmp/${headers[0]}"

rm $enctmp
filehash=$(sha256sum "/tmp/${headers[0]}" | cut -d " " -f 1)
if [ "${headers[1]}" != "$filehash" ]
then
   echo "Decrypted file SHA-256 check failed"
   rm "/tmp/${headers[0]}"
   exit -1
else
   echo "Decrypted file saved to: /tmp/${headers[0]}"
fi
```

**Example encryption and decryption**

Encrypt on Windows<br />
![alt text](https://github.com/billchaison/wincrypt/raw/main/wc0.png)

Decrypt on Linux<br />
![alt text](https://github.com/billchaison/wincrypt/raw/main/wc1.png)
