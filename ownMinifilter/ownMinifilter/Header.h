#pragma once

#include <string.h>

/////////////Distributed Access Control/////////////////////

#define MAX_FILE_AMOUNT 20
#define MAX_PROCESS_AMOUNT 20
#define MAX_FILE_NAME_LENGTH 2048
#define MAX_PROCESS_NAME_LENGTH 2048

typedef struct DAC_PROCESS
{
	char executor[MAX_PROCESS_NAME_LENGTH];
	char processName[MAX_PROCESS_NAME_LENGTH];

}DAC_PROCESS;

unsigned int dacProcessCounter = 0;
DAC_PROCESS dacProcessList[MAX_PROCESS_AMOUNT] = { 0 };

typedef struct DAC_FILE
{
	char user[MAX_PROCESS_NAME_LENGTH];
	char fileName[MAX_PROCESS_NAME_LENGTH];
	char rights[MAX_PROCESS_NAME_LENGTH];

}DAC_FILE;

unsigned int dacFileCounter = 0;
DAC_FILE dacFileList[MAX_FILE_AMOUNT] = { 0 };

int compareStrings(char* first, const char* second)
{
	while (*first && *second)
	{
		if (*first != *second) return 0;
		++first;
		++second;
	}
	return 1;
}

void dacAddUsersToList(char* data)
{
	char* line_tok = NULL;
	char* _line_tok = NULL;
	char* arg_tok = NULL;
	char* _arg_tok = NULL;

	while (1) {
		if (line_tok == NULL)
			line_tok = strtok_s(data, "\n", &_line_tok);
		else
			line_tok = strtok_s(NULL, "\n", &_line_tok);

		if (line_tok == NULL)
			break;

		arg_tok = strtok_s(line_tok, " ", &_arg_tok);
		strcpy(dacProcessList[dacProcessCounter].processName, arg_tok);
		arg_tok = strtok_s(NULL, " ", &_arg_tok);
		strcpy(dacProcessList[dacProcessCounter].executor, arg_tok);

		dacProcessCounter++;
	}

}

void dacAddFilesToList(char* data)
{
	char* line_tok = NULL;
	char* _line_tok = NULL;
	char* arg_tok = NULL;
	char* _arg_tok = NULL;

	while (1) {

		if (line_tok == NULL)
			line_tok = strtok_s(data, "\n", &_line_tok);
		else
			line_tok = strtok_s(NULL, "\n", &_line_tok);

		if (line_tok == NULL)
			break;

		arg_tok = strtok_s(line_tok, " ", &_arg_tok);
		strcpy(dacFileList[dacFileCounter].fileName, arg_tok);

		arg_tok = strtok_s(NULL, " ", &_arg_tok);

		strcpy(dacFileList[dacFileCounter].user, arg_tok);
		arg_tok = strtok_s(NULL, " ", &_arg_tok);

		if (compareStrings(arg_tok, "rw")) {
			strcpy(dacFileList[dacFileCounter].rights, arg_tok);
		}
		else if (compareStrings(arg_tok, "w"))
			strcpy(dacFileList[dacFileCounter].rights, arg_tok);
		else if (compareStrings(arg_tok, "r"))
			strcpy(dacFileList[dacFileCounter].rights, arg_tok);

		dacFileCounter++;
	}
}

void getExecutor(char procname[MAX_FILE_NAME_LENGTH], char* useri) {

	for (unsigned int counter = 0; counter < dacProcessCounter; counter++)
	{
		if (compareStrings(procname, dacProcessList[counter].processName))
		{
			strcpy(useri, dacProcessList[counter].executor);

		}
	}
}

//0(false) - denied, 1(true) - allowed
//request 0x3 - read, 0x4 - write
int is_allowed(char user[MAX_PROCESS_NAME_LENGTH], char file[MAX_PROCESS_NAME_LENGTH], unsigned int request) {
	if (request == 0x03) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DEBUG: IRP_MJ_READ request\n");
		for (unsigned int counter = 0; counter < dacFileCounter; counter++) {
			if (compareStrings(file, dacFileList[counter].fileName)) {
				if (compareStrings(user, dacFileList[counter].user)){
					if (compareStrings("r", dacFileList[counter].rights) || compareStrings("rw", dacFileList[counter].user)) {
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "***ACCESS: ALLOWED\n");
						return 1;
					}
				}
			}

		}
	}
	else if (request == 0x04) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DEBUG: IRP_MJ_WRITE request\n");
		for (unsigned int counter = 0; counter < dacFileCounter; counter++) {
			if (compareStrings(file, dacFileList[counter].fileName)) {
				if (compareStrings(user, dacFileList[counter].user)) {
					if (compareStrings("w", dacFileList[counter].rights) || compareStrings("rw", dacFileList[counter].user)) {
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "***ACCESS: ALLOWED\n");
						return 1;
					}
				}
			}
		}
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Unknown request, please do IRP_MJ_WRITE or IRP_MJ_READ\n");	
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "***ACCESS: DENIED\n");
	return 0;
}


int dacProcessExistInList(char name[MAX_PROCESS_NAME_LENGTH])
{
	for (unsigned int counter = 0; counter < dacProcessCounter; counter++)
	{
		if (compareStrings(name, dacProcessList[counter].processName))
			return 1;
	}
	return 0;
}

int dacFileExistInList(char name[MAX_FILE_NAME_LENGTH])
{
	for (unsigned int counter = 0; counter < dacFileCounter; counter++)
	{
		//if (compareStrings(name, dacFileList[counter].fileName))
			//return 1;
		if (strncmp(dacFileList[counter].fileName, name, strlen(dacFileList[counter].fileName))==0)
			return 1;
	}
	return 0;
}