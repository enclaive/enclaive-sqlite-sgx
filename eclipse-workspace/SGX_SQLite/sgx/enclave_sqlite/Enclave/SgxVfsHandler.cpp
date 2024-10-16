#include <string.h>
#include <mutex>
#include <assert.h>
#include <random>
#include "sqlite3.h"

#include "../Enclave/Enclave_t.h"
#include "../Enclave/sqlite3.h"
#include "sgx_tprotected_fs.h"



#include "sgx_urts.h"

bool debugFlag = false;

std::string getSgxVfsName() {
	static std::mutex mutex;
	std::lock_guard<std::mutex> lock(mutex);

	static const char *vfsName = "sgx_vfs_handler";
	if (sqlite3_vfs_find(vfsName) != nullptr)
		return vfsName;

	struct File: sqlite3_file {
		SGX_FILE *sgxData;         // pointer to the source stream
		int lockLevel; 			   // level of lock by SQLite ; goes from 0 (not locked) to 4 (exclusive lock)
		const char* fileName;
	};

	static_assert(offsetof(File, pMethods) == 0, "Wrong data alignment in custom SQLite3 VFS, lots of weird errors will happen during runtime");

	struct Functions {
		static int xOpen(sqlite3_vfs*, const char *zName,
				sqlite3_file *fileBase, int flags, int *pOutFlags) {

			static sqlite3_io_methods methods;
			methods.iVersion = 1;
			methods.xClose = &xClose;
			methods.xRead = &xRead;
			methods.xWrite = &xWrite;
			methods.xTruncate = &xTruncate;
			methods.xSync = &xSync;
			methods.xFileSize = &xFileSize;
			methods.xLock = &xLock;
			methods.xUnlock = &xUnlock;
			methods.xCheckReservedLock = &xCheckReservedLock;
			methods.xFileControl = &xFileControl;
			methods.xSectorSize = &xSectorSize;
			methods.xDeviceCharacteristics = &xDeviceCharacteristics;
			fileBase->pMethods = &methods;

			if (debugFlag) ocall_println_string("Open");

			auto fileData = static_cast<File*>(fileBase);
			fileData->fileName = zName;

			fileData->sgxData = sgx_fopen_auto_key(zName, "rb+");

			if (fileData->sgxData == NULL) {
				fileData->sgxData = sgx_fopen_auto_key(zName, "wb+");
			}

            return SQLITE_OK;
		}

		static int xClose(sqlite3_file *fileBase) {
			if (debugFlag) ocall_println_string("Close");
			int32_t result = 0;
			int32_t error = 0;

			result = sgx_fclose(static_cast<File*>(fileBase)->sgxData);
			error = sgx_ferror(static_cast<File*>(fileBase)->sgxData);

		if (result == 1)
				return SQLITE_IOERR_CLOSE;
			return SQLITE_OK;
		}

		static int xRead(sqlite3_file *fileBase, void *buffer, int quantity,
				sqlite3_int64 offset) {
			int32_t error;
			int resultSeek = 0;
			int resultRead = 0;

			resultSeek = sgx_fseek(static_cast<File*>(fileBase)->sgxData,
					offset, SEEK_SET);
			error = sgx_ferror(static_cast<File*>(fileBase)->sgxData);

			if (resultSeek == -1) {
				return SQLITE_IOERR_SEEK;
			}

			resultRead = sgx_fread(buffer, sizeof(char), quantity,
					static_cast<File*>(fileBase)->sgxData);
			error = sgx_ferror(static_cast<File*>(fileBase)->sgxData);


			return SQLITE_OK;
		}

		static int xWrite(sqlite3_file *fileBase, const void *buffer,
				int quantity, sqlite3_int64 offset) {
			int32_t resultSeek = 0;
			int32_t resultWrite = 0;

			auto fileData = static_cast<File*>(fileBase);

			// Sometimes the byte offset (position of where to write the buffer) is larger than
			// the complete file size, which causes sgx_fseek to fail (it searches somewhere behind the file).
			// To fix this, dummy bytes are written to the end of the file to extend its 
			// size so that sgx_fseek in any case finds the offset within the file
			sgx_fseek(fileData->sgxData, 0, SEEK_END);
			int64_t fileSize = sgx_ftell(fileData->sgxData);
			if (offset > fileSize) {
				int64_t diff = offset-fileSize;
				char dummy[diff] = { 0 };
				sgx_fwrite(dummy, sizeof(char), diff, fileData->sgxData);
			}

			resultSeek = sgx_fseek(fileData->sgxData, offset, SEEK_SET);
			if (resultSeek == -1) {
				return SQLITE_IOERR_SEEK;
			}

			resultWrite = sgx_fwrite(buffer, sizeof(char), quantity,
					fileData->sgxData);

			if (resultWrite == 0) {
				return SQLITE_IOERR_WRITE;
			}

			return SQLITE_OK;
		}

		static int xSync(sqlite3_file *fileBase, int) {
			sgx_fflush(static_cast<File*>(fileBase)->sgxData);
			return SQLITE_OK;
		}

		static int xFileSize(sqlite3_file *fileBase,
				sqlite3_int64 *outputSize) {
			uint64_t file_size = 0;
			sgx_fseek(static_cast<File*>(fileBase)->sgxData, 0, SEEK_END);
			file_size = sgx_ftell(static_cast<File*>(fileBase)->sgxData);

			*outputSize = file_size;

			return SQLITE_OK;
		}

		static int xLock(sqlite3_file *fileBase, int level) {
			if (debugFlag) ocall_println_string("LOCK");
			static_cast<File*>(fileBase)->lockLevel = level;
			return SQLITE_OK;
		}

		static int xUnlock(sqlite3_file *fileBase, int level) {
			if (debugFlag) ocall_println_string("UNLOCK");
			static_cast<File*>(fileBase)->lockLevel = level;
			return SQLITE_OK;
		}

		static int xCheckReservedLock(sqlite3_file *fileBase, int *pResOut) {
			File *fileData = static_cast<File*>(fileBase);
			*pResOut = (fileData->lockLevel >= 1);
			return SQLITE_OK;
		}

		static int xFileControl(sqlite3_file *fileBase, int op, void *pArg) {

			auto fileData = static_cast<File*>(fileBase);

			switch (op) {
			case SQLITE_FCNTL_LOCKSTATE:
				*reinterpret_cast<int*>(pArg) = fileData->lockLevel;
				break;

			case SQLITE_FCNTL_SIZE_HINT:
				// gives a hint about the size of the final file in reinterpret_cast<int*>(pArg)
				// not implemented
				if (debugFlag) ocall_println_string("xFileControl : SQLITE_FCNTL_SIZE_HINT");
				break;

			case SQLITE_FCNTL_CHUNK_SIZE:
				// gives a hint about the size of blocks of data that SQLite will write at once
				// not implemented
				if (debugFlag) ocall_println_string("xFileControl : SQLITE_FCNTL_CHUNK_SIZE");
				break;

			case SQLITE_GET_LOCKPROXYFILE:
				return SQLITE_ERROR;
			case SQLITE_SET_LOCKPROXYFILE:
				return SQLITE_ERROR;
			case SQLITE_LAST_ERRNO:
				return SQLITE_ERROR;
			}

			return SQLITE_OK;
		}

		static int xSectorSize(sqlite3_file*) {
			return 512;
		}

		static int xDeviceCharacteristics(sqlite3_file*) {
			return SQLITE_IOCAP_ATOMIC | SQLITE_IOCAP_SAFE_APPEND
					| SQLITE_IOCAP_SEQUENTIAL;
		}

		static int xAccess(sqlite3_vfs*, const char *zName, int flags,
				int *pResOut) {
			*pResOut = (strlen(zName) == sizeof(void*) * 2);
			return SQLITE_OK;
		}

		static int xFullPathname(sqlite3_vfs*, const char *zName, int nOut,
				char *zOut) {
			std::strncpy(zOut, zName, nOut); // @suppress("Function cannot be resolved")

			return SQLITE_OK;
		}

		static int xCurrentTime(sqlite3_vfs*, double *output) {
			static const double unixEpoch = 2440587.5;

			if (debugFlag) ocall_println_string("xCurrentTimeInt64");

			*output = unixEpoch + 1 / (60.*60.*24.);
			return SQLITE_OK;
		}

		static int xCurrentTimeInt64(sqlite3_vfs*, sqlite3_int64 *output) {
			static const sqlite3_int64 unixEpoch = 24405875
					* sqlite3_int64(60 * 60 * 24 * 100);

			if (debugFlag) ocall_println_string("xCurrentTimeInt64");

			*output = unixEpoch + 1 * 1000;
			return SQLITE_OK;
		}

		static int xRandomness(sqlite3_vfs*, int nByte, char *zOut) {
			// this function generates a random serie of characters to write in 'zOut'
			// not implemented
			if (debugFlag) ocall_println_string("xRandomness");
			return SQLITE_OK;
		}

		static int xDelete(sqlite3_vfs*, const char *zName, int syncDir) {
			if (debugFlag) ocall_println_string("xDelete");
			int32_t resultRemove = 0;
			resultRemove = sgx_remove(zName);
			return SQLITE_OK;
		}

		static int xTruncate(sqlite3_file *fileBase, sqlite3_int64 size) {
			if (debugFlag)ocall_println_string("xTruncate");
			// it is not possible to truncate a stream
			// it makes sense to truncate a file or a buffer, but not a generic stream
			// however it is possible to implement the xTruncate function as a no-op
			// not implemented
			return SQLITE_OK;
		}

		static int xSleep(sqlite3_vfs*, int microseconds) {
			if (debugFlag) ocall_println_string("xSleep");
			//not implemented
			return SQLITE_OK;
		}

	};

	// creating the VFS structure
	static sqlite3_vfs readStructure;
	memset(&readStructure, 0, sizeof(readStructure));
	readStructure.iVersion = 2;
	readStructure.szOsFile = sizeof(File);
	readStructure.mxPathname = 256;
	readStructure.zName = vfsName;
	readStructure.pAppData = nullptr;
	readStructure.xOpen = &Functions::xOpen;
	readStructure.xDelete = &Functions::xDelete;
	readStructure.xAccess = &Functions::xAccess;
	readStructure.xFullPathname = &Functions::xFullPathname;
	/*readStructure.xDlOpen = &Functions::xOpen;
	 readStructure.xDlError = &Functions::xOpen;
	 readStructure.xDlSym = &Functions::xOpen;
	 readStructure.xDlClose = &Functions::xOpen;*/
	readStructure.xRandomness = &Functions::xRandomness;
	readStructure.xSleep = &Functions::xSleep;
	readStructure.xCurrentTime = &Functions::xCurrentTime;
	//readStructure.xGetLastError = &Functions::xOpen;
	readStructure.xCurrentTimeInt64 = &Functions::xCurrentTimeInt64;

	// the second parameter of this function tells if
	//   it should be made the default file system
	sqlite3_vfs_register(&readStructure, false);

	return vfsName;
}

