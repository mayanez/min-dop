#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

// Maximum outstanding connection requests
#define MAXPENDING        1

#define MAXCONN           1024
#define VULN_BUF_LEN      8
#define RECV_MAX_LEN      1024
#define SCRATCH_BUF_LEN   100

typedef int var_t;
typedef int *var_p_t;
typedef int g_var_t;
typedef int *g_var_p_t;
typedef int **g_var_pp_t;

typedef struct {
  g_var_p_t p_a;
  g_var_pp_t pp_b;
  g_var_p_t p_c;
  var_t v_1;
  var_t v_2;
} g_struct_t;

typedef g_struct_t *g_struct_p_t;

#ifdef CODE_COVERAGE
void __gcov_flush(void);
#endif

////////////////////////////////////////////////////////////////////////////////
// GLOBAL DATA START

g_var_t g_clfd;

g_var_t g_is_root = 0;
g_var_t g_d = 0;
g_var_t g_c = 0;
g_var_t *g_p_c = &g_c;
g_var_t g_b= 0;
g_var_t *g_p_b = &g_b;
g_var_t g_a = 0;

g_struct_t g_srv = {&g_a, &g_p_b, &g_c, 0, 0};

g_var_t SECRET = 0x1337;

g_var_t TYPE_NONE      = 3;
g_var_t TYPE_ADD       = 4;
g_var_t TYPE_GETPRIV   = 5;
g_var_t TYPE_SETPRIV   = 6;
g_var_t TYPE_GET       = 7;
g_var_t TYPE_STORE     = 8;
g_var_t TYPE_LOAD      = 9;
g_var_t TYPE_MAX       = 10;

// Lookup table for the error code for given "type" <= 2
g_var_t LUT_ERROR_CODES[] = {
  0xfffffd00,
  0xfffffe01,
  0xffffff02
};

g_var_p_t g_p_secret = &SECRET;
g_var_pp_t g_pp_secret = &g_p_secret;

g_var_p_t g_p_g_a = &g_a;
g_var_pp_t g_pp_g_a = &g_p_g_a;

g_var_p_t g_p_g_is_root = &g_is_root;
g_var_pp_t g_pp_g_is_root = &g_p_g_is_root;

g_var_t g_scratch_buf[SCRATCH_BUF_LEN] = {0};
g_var_p_t g_p_scratch_buf = &g_scratch_buf[0];
g_var_pp_t g_pp_scratch_buf = &g_p_scratch_buf;

// GLOBAL DATA END
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// "STACK" VARIABLES
// NOTE: This is done to make symbol information more easily available.
// For our purposes, the overflow would work in the same fashion (whether stack or global).
char sbuf[VULN_BUF_LEN] = {0};
volatile var_t padding1 = 0; // NOTE: These are for alignment purposes.
volatile var_t padding2 = 0; // Different compilers add different padding.
volatile var_t padding3 = 0;
var_t connect_limit = MAXCONN;
g_struct_p_t p_srv = &g_srv;
g_var_p_t p_g_d = &g_d;
// "STACK" VARIABLES STOP
////////////////////////////////////////////////////////////////////////////////

//
// Read incoming data from remote client and copy to *vulnerable* buffer.
//
int readInData(int clientfd, char *buf)
{
  char buffer[RECV_MAX_LEN] = {0};
  unsigned int recv_len;

  // Get data from client
  recv_len = recv(clientfd, buffer, RECV_MAX_LEN, 0);
  // GCOVR_EXCL_START
  if (recv_len == -1) {
    close(clientfd);
    return -1;
  }
  // GCOVR_EXCL_STOP

  printf("[readInData] received bytes: %d\n", recv_len);

  memcpy(buf, buffer, recv_len);
  return 0;
}


//
// Check for invalid types (<= 2) and send error code to client if so.
//
int checkForInvalidTypes(var_t type, int clientfd)
{
  char buffer[10] = {0};
  int err_no;

  // integer underflow
  if (type <= 2) {
    err_no = LUT_ERROR_CODES[type];
    printf("[checkForInvalidTypes] ERROR: err_no:%x\n", err_no);
    sprintf(buffer, "%08x\n", err_no);
    send(clientfd, buffer, 9, 0);
    return 1;
  }
  return 0;
}

//
// Return value of g_a as reply
//
void getG_A(int clientfd)
{
  char buffer[20] = {0};

  // Memory Disclosure
  printf("[get] g_a:%x\n", *g_p_g_a);
  sprintf(buffer, "g_a:%x\n", *g_p_g_a);
  send(clientfd, buffer, 20, 0);
}

//
// Return privilege level as reply
//
void getPrivLevel(int clientfd)
{
  char buffer[20] = {0};

  printf("[getPrivLevel] g_is_root: %x\n", g_is_root);
  if (!g_is_root) {
    sprintf(buffer, "priv:NORMAL\n");
  } else {
    sprintf(buffer, "priv:ROOT\n");
  }
  send(clientfd, buffer, 20, 0);
}


//
// Set privilege level to root if "s" matches magic password
//
void setPrivLevel(int s, int clientfd)
{
  char buffer[20] = {0};

  printf("SECRET?:%d\n", s);
  if (s == SECRET) {
    g_is_root = 1;
    sprintf(buffer, "priv:ROOT\n");
  } else {
    sprintf(buffer, "priv:NORMAL\n");
  }
  send(clientfd, buffer, 20, 0);
}

//
// Accepts incoming connections. Returns 0 if error in connection or limit is up
//
int doListen(int sockfd, var_t *connect_limit)
{
  struct sockaddr_in client_addr;
  unsigned int addrlen = sizeof(client_addr);
  if (*connect_limit == 0)
    return 0;
  int clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &addrlen);
  // GCOVR_EXCL_START
  if (clientfd == -1)
    return 0;
  // GCOVR_EXCL_STOP
  (*connect_limit)--;
  return clientfd;
}


//
// Main server loop.
//
void do_serve(int sockfd)
{
  var_p_t p_size = 0;
  var_p_t p_type = 0;

  // gadget dispatcher
  while ((g_clfd = doListen(sockfd, &connect_limit))) {

    printf("\n[do_serve] Request Start:\n");
    printf("[do_serve] internal stack variables:\n");
    printf("            p_g_d: <%p>\n", p_g_d);
    printf("            p_srv: <%p>\n", p_srv);
    printf("    connect_limit:  %x\n", connect_limit);
    printf("           p_size: <%p>\n", p_size);
    printf("           p_type: <%p>\n", p_type);

    // for simplicity, reset p_size, p_type
    p_size = (var_t *)&sbuf[4];
    p_type = (var_t *)&sbuf[0];

    readInData(g_clfd, sbuf);                    // memory write safety violation

    // DEBUG
    printf("[do_serve] received output:\n<--\n");
    for(int i = 0; i < 28; i++) {
      printf("%x", sbuf[i]);
    }
    printf("\n-->\n");

    printf("[do_serve] internal stack variables:\n");
    printf("            p_g_d: <%p>\n", p_g_d);
    printf("            p_srv: <%p>\n", p_srv);
    printf("    connect_limit:  %x\n", connect_limit);
    printf("           p_size: <%p>\n", p_size);
    printf("          *p_size:  %x\n", *p_size);
    printf("           p_type: <%p>\n", p_type);
    printf("          *p_type:  %x\n", *p_type);

    if (checkForInvalidTypes(*p_type, g_clfd)) { // memory read safety violation
      close(g_clfd);
      continue;
    }

    if (*p_type == TYPE_NONE) {
      close(g_clfd);
      break;
    }

    if (*p_type == TYPE_ADD) {                                  // DOP: condition
      printf("[do_serve] TYPE_ADD\n");
      p_srv->v_1 += *p_size;                                    // DOP: addition
    } else if (*p_type == TYPE_GETPRIV) {
      printf("[do_serve] TYPE_GETPRIV\n");
      getPrivLevel(g_clfd);
    } else if (*p_type == TYPE_SETPRIV) {
      printf("[do_serve] TYPE_SETPRIV\n");
      setPrivLevel(*p_size, g_clfd);
    } else if (*p_type == TYPE_GET) {
      printf("[do_serve] TYPE_GET\n");
      getG_A(g_clfd);
    } else if (*p_type == TYPE_STORE) {
      printf("[do_serve] TYPE_STORE\n");
      **(p_srv->pp_b) = *p_g_d;                                 // DOP: store
    } else if (*p_type == TYPE_LOAD) {
      printf("[do_serve] TYPE_LOAD\n");
      *p_g_d = **(p_srv->pp_b);                                 // DOP: load
    } else {
      printf("[do_serve] TYPE_ASSIGN\n");
      p_srv->v_2 = *p_size;                                     // DOP: assignment
    }

    close(g_clfd);
#ifdef CODE_COVERAGE
    __gcov_flush();
#endif
  }
}

// GCOVR_EXCL_START
void usage(char *progname)
{
  printf("usage: %s port\n", progname);
}
// GCOVR_EXCL_STOP


int main(int argc, char **argv)
{
  // GCOVR_EXCL_START
  int sockfd;
  struct sockaddr_in self;

  if (argc < 2) {
    usage(argv[0]);
    return -1;
  }

  // Create streaming socket
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Socket");
    exit(errno);
  }

  // Initialize address/port structure
  memset(&self, 0, sizeof(self));
  self.sin_family = AF_INET;
  self.sin_port = htons(atoi(argv[1]));
  self.sin_addr.s_addr = INADDR_ANY;

  // Allow reuse of address
  int yes = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    perror("setsockopt");
    exit(errno);
  }

  // Assign a port number to the socket
  if (bind(sockfd, (struct sockaddr*)&self, sizeof(self)) != 0) {
    perror("socket-bind");
    exit(errno);
  }

  // Make it a "listening socket"
  if (listen(sockfd, MAXPENDING) != 0) {
    perror("socket-listen");
    exit(errno);
  }
  // GCOVR_EXCL_STOP

  printf("[main] listening on port %d...\n", atoi(argv[1]));

  // Serve for love
  do_serve(sockfd);

  return 0;
}
