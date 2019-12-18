#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>

void error(const char*msg)
{
	perror(msg);
	exit(1);
}

int main(int argc,char*argv[])
{
	if(argc < 2)
	{
		fprintf(stderr,"Port Number not provided, program terminated\n");
		exit(1);
	}
	
	int sockfd,newsockfd,portno,n;
	char buffer[255];
	
	struct sockaddr_in serv_addr,cli_addr;
	socklen_t client;
	
	sockfd = socket(AF_INET,SOCK_STREAM,0);
	if(sockfd < 0)
	{
		error("Error in openning socket");
	}
	
	bzero((char*) &serv_addr,sizeof(serv_addr));
	portno = atoi(argv[1]);
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	
	if(bind(sockfd,(struct sockaddr*) &serv_addr,sizeof(serv_addr)) < 0)
	{
		error("Binding Failed");
	}
	
	listen(sockfd,5);
	client = sizeof(cli_addr);
	
	newsockfd = accept(sockfd, (struct sockaddr*) &cli_addr, &client);
	
	if(newsockfd < 0)
	{	
		error("Error on Accept");
	}
	
	while(1)
	{
		bzero(buffer,256);
		n = read(newsockfd,buffer,255);
		if(n < 0)
		{
			error("Error on reading");
		}
		printf("Client : %s\n", buffer);
		bzero(buffer,255);
		fgets(buffer,255,stdin);
		
		n = write(newsockfd,buffer,strlen(buffer));
		if(n < 0)
		{
			error("Error on writing");
		}
		
		int i = strncmp("Bye",buffer,3);
		
		if(i == 0)
		{
			break;
		}
	}
	
	close(newsockfd);
	close(sockfd);
	
	return 0;
}
