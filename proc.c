#define _BSD_SOURCE				//Get getpass() declaration
#define _XOPEN_SOURCE			//Get crypt() declaration

#include<stdio.h>
#include<unistd.h>
#include<limits.h>
#include<pwd.h>
#include<shadow.h>
#include<malloc.h>
#include<string.h>
#include<signal.h>
#include<fcntl.h>

typedef int BOOL;

#define TRUE 1
#define FALSE 0
#define UREAD 2
#define UWRITE 3

BOOL encription(uid_t*);
static void procStart(int);
BOOL openFile();
BOOL writeFile();
BOOL readFile();

int j = 0;
int fd = 0;
pid_t pid;
char buffer[5] = {'\0'};

int main(int argc,char*argv[])
{
	struct passwd*pwd;
	
	pid = getpid();
	//Call to encryption() for authentication
	if(encription(&(pwd->pw_uid)) == FALSE)
	{
		printf("Incorrect Password\n");
		return -1;
	}
	else
	{
		printf("Successfully authenticated : UID = %ld\n",(long)pwd->pw_uid);

		//Open the text file
		fd = openFile();
		if(fd == FALSE)
		{
			printf("Unable to open the file\n");
			return -1;
		}

		//Signal Passed to pause the process
		if(signal(SIGINT,procStart) == SIG_ERR)
		{
			printf("Signal Error\n");
		}
		//kill(pid, SIGCONT);
		if(readFile() == UREAD)
		{
			printf("Unable to read\n");
			return -1;
		}

		j = atoi(buffer);
		while(1)
		{
			printf("%d\n",j);
			j++;
			sleep(1);
		}
	}

	return 0;
}

BOOL encription(uid_t* userId)
{
	char*username,*password,*encrypted,*p;
	struct passwd*pwd;
	struct spwd*spwd;
	BOOL authOk;
	size_t len;
	long lnmax;
	
	lnmax = sysconf(_SC_LOGIN_NAME_MAX);
	if(lnmax == -1)							//If limit is interminate
	{
		lnmax = 256;
	}
	username = malloc(lnmax);
	if(username == NULL)
	{
		printf("Malloc Error\n");
		return FALSE;
	}
	
	printf("Username : ");
	fflush(stdout);
	
	if(fgets(username,lnmax,stdin) == NULL)
	{
		printf("fgets Error\n");
		return FALSE;
	}
	
	len = strlen(username);
	if(username[len-1] == '\n')
	{
		username[len-1] = '\0';				//Remove \n
	}
	
	pwd = getpwnam(username);
	if(pwd == NULL)
	{
		printf("ERROR : Couldn't get password record\n");
		return FALSE;
	}
	
	spwd = getspnam(username);
	if(spwd == NULL)
	{
		printf("No permission to read shadow password file\n");
		return FALSE;
	}
	
	if(spwd != NULL)
	{
		pwd->pw_passwd = spwd->sp_pwdp;
	}
	
	password = getpass("Password : ");
	
	//Encrypt password & erase cleartext version immediately
	
	encrypted = crypt(password,pwd->pw_passwd);
	for(p=password;*p != '\0';)
	{
		*p++ = '\0';
	}
	
	if(encrypted == NULL)
	{
		printf("Crypt Error\n");
	}
	
	authOk = strcmp(encrypted,pwd->pw_passwd) == 0;
	if(!authOk)
	{
		return FALSE;
	}
	else
	{
		*userId = pwd->pw_uid;
		return TRUE;
	}
}

static void procStart(int sig)
{
	printf("\nProcess Stopped at %d\n",j);
	
	if(writeFile() == UWRITE)
	{
		printf("Unable to write\n");
	}

	kill(pid, SIGSTOP);
}

BOOL openFile()
{
	int fd = 0;

	fd = open("test.txt",O_RDWR);
	if(fd == -1)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL writeFile()
{
	int fd = 0,iwrite = 0;
	char buff[4] = {'\0'};
	
	fd = open("test.txt",O_WRONLY);
	if(fd == -1)
	{
		printf("Unable to open the file\n");
		return FALSE;
	}
	
	sprintf(buff,"%1d",j);
	
	iwrite = write(fd,buff,strlen(buff));
	if(iwrite == -1)
	{
		return UWRITE;
	}
	return TRUE;
}

BOOL readFile()
{
	int iRet = 0, fd = 0;
	
	fd = open("test.txt",O_RDONLY);
	iRet = read(fd,buffer,5);
	if(iRet == -1)
	{
		return UREAD;
	}
	sleep(1);
}
