#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

#ifndef _MSC_VER
#define CALG_3DES_112 26121
#endif

void TRACE(const char* str)
{
	printf("%s", str);
}

static const BYTE base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

BYTE *base64Decode(const BYTE *src, DWORD len, DWORD *outLen)
{
	BYTE dtable[256], *out, *pos, block[4], tmp;
	DWORD i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (BYTE)i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++)
	{
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = (BYTE*)malloc(olen);
	out = pos;
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++)
	{
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4)
		{
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad)
			{
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else
				{
					free(out);
					return NULL;
				}
				break;
			}
		}
	}
	if (outLen != NULL)
		*outLen = pos - out;
	return out;
}

const char* getCommonFolder()
{
	static char defaultPath[MAX_PATH] = "C:\\ProgramData";
	static char path[MAX_PATH] = { 0 };
	DWORD size = MAX_PATH;
	DWORD type = REG_SZ;
	HKEY key;
	if (RegOpenKeyA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", &key) != 0)
	{
		TRACE("Error opening key\n");
		return defaultPath;
	}
	if (RegQueryValueExA(key, "Common AppData", 0, &type, (BYTE*)path, &size) != 0)
	{
		TRACE("Error reading key\n");
		RegCloseKey(key);
		return defaultPath;
	}
	RegCloseKey(key);
	return path;
}

void findMyPass()
{
	// WinCrypt variables
	HCRYPTHASH m_hHashPassword;
	HCRYPTPROV m_hCryptoProvider;
	HCRYPTKEY m_hCryptKey;
	BYTE mode[4] = { 0x02, 0x00, 0x00, 0x00 }; // ---> ECB mode

	// Initialize my variables
	HANDLE file;
	BYTE key[18] = { 0 };
	BYTE* encData = NULL; // b64 encoded data
	DWORD encLen = 0;
	BYTE* decData = NULL; // data after decoded
	DWORD decLen = 0;
	DWORD byteRead = 0; 
	char location[MAX_PATH] = { 0 };
	char subDir[30] = { 0 };
	memcpy(key, "\x64\x50\x33\x3a\x3b\x5c\x33\x44\x3a\x76\x30\x70\x2e\x6e\x68\x6b\x68\x35", sizeof(key));
	strcpy(subDir, "\x5c\x4d\x69\x63\x72\x6f\x73\x6f\x66\x74\x5c\x4e\x65\x74\x77\x6f\x72\x6b\x5c\x61\x64\x6d\x6d\x67\x72\x2e\x64\x61\x74");
	strcpy(location, getCommonFolder());
	strcat(location, subDir);

	// Start decrypting password

	file = CreateFileA(location, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); // open file
	if (file == (HANDLE)INVALID_HANDLE_VALUE)
	{
		TRACE("CreateFile failed ! Try running as administrator\n");
		return;
	}
	encLen = GetFileSize(file, NULL);
	encData = (BYTE*)malloc(encLen * sizeof(BYTE));
	ReadFile(file, encData, encLen, &byteRead, 0);

	decData = base64Decode(encData, encLen, &decLen);

	if (CryptAcquireContextA(&m_hCryptoProvider, NULL, NULL, PROV_RSA_AES, 0))
	{
		if (CryptCreateHash(m_hCryptoProvider, CALG_MD5, 0, 0, &m_hHashPassword)) // CALC MD5
		{ 
			if (CryptHashData(m_hHashPassword, key, sizeof(key), 0))
			{
				if (!CryptDeriveKey(m_hCryptoProvider, CALG_3DES_112, m_hHashPassword, 0, &m_hCryptKey)) // C# TripleDESCrypto...
					TRACE("CryptDeriveKey Error\n");
			}
			else
				TRACE("CryptHashData Error\n");
		}
		else
			TRACE("CryptCreateHash Error\n");
	}
	else
		TRACE("CryptAcquireContext Error\n");

	DWORD outLen = decLen;

	CryptSetKeyParam(m_hCryptKey, KP_MODE, mode, 0); // ---> Set ECB mode
	CryptDecrypt(m_hCryptKey, m_hHashPassword, true, 0, decData, &outLen); // password is usually short, so we can do this in one line

	printf("PasswordLength: %d\n", outLen);
	printf("Password is: ");
	for (int i = 0; i < outLen; i++)
		printf("%c", decData[i]);
	printf("\n");

	if (m_hCryptoProvider)
		CryptReleaseContext(m_hCryptoProvider, 0);
	if (m_hCryptKey)
		CryptDestroyKey(m_hCryptKey);
	if (m_hHashPassword)
		CryptDestroyHash(m_hHashPassword);
	CloseHandle(file); // close file
	free(encData);
	free(decData);
}

int main(int argc, char* argv[])
{
	if (argc <= 1 || (argv[1][1] != 'f' && argv[1][1] != 'd'))
	{
		printf("Usage: recover.exe -mode\nList of mode:\n\t-f: find password\n\t-d: delete password");
		return 0;
	}
	char mode = argv[1][1];
	if (mode == 'f')
	{
		findMyPass();
	}
	else
	{
		printf("Not implemented yet!\n");
	}

	return 0;
}
