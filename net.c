#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "net.h"
#include "jbod.h"


/* the client socket descriptor for the connection to the server */
int cli_sd = -1;

int socksd;
struct sockaddr_in caddr;

/* attempts to read n bytes from fd; returns true on success and false on
 * failure */
static bool nread(int fd, int len, uint8_t *buf) {
  int num_read = 0;

  while(num_read < len)
  {
    int n = read(fd, &buf[num_read], len - num_read);

    if (n < 0)
    {
      return false;
    }

    num_read += n;
  }
  return true;
}

/* attempts to write n bytes to fd; returns true on success and false on
 * failure */
static bool nwrite(int fd, int len, uint8_t *buf) {
  int num_write = 0;

  while(num_write < len)
  {
    int n = write(fd, &buf[num_write], len - num_write);

    if (n < 0)
    {
      return false;
    }

    num_write += n;
  }
  return true;
}

/* attempts to receive a packet from fd; returns true on success and false on
 * failure */
static bool recv_packet(int fd, uint32_t *op, uint16_t *ret, uint8_t *block) {
  uint8_t header[HEADER_LEN];
  uint16_t len;
  
  if(!nread(fd, HEADER_LEN, header))
  {
    return false;
  }

  memcpy(&len, header, sizeof(len));
  memcpy(op, header + 2, sizeof(*op));
  memcpy(ret, header + 6, sizeof(*ret));

  len = ntohs(len);
  *op = ntohl(*op);
  *ret = ntohs(*ret);

  if(len == HEADER_LEN + JBOD_BLOCK_SIZE)
  {
    if(!nread(fd, JBOD_BLOCK_SIZE, block))
    {
      return false;
    }
  }
  
  return true;
}

/* attempts to send a packet to sd; returns true on success and false on
 * failure */
static bool send_packet(int sd, uint32_t op, uint8_t *block) {
  uint16_t len = HEADER_LEN;
  uint32_t cmd = op >> 26;
  uint8_t sendbuf[HEADER_LEN];

  if (cmd == JBOD_WRITE_BLOCK)
  {
    len += JBOD_BLOCK_SIZE;
  }

  len = htons(len);
  op = htonl(op);

  memcpy(sendbuf, &len, sizeof(len));
  memcpy(sendbuf + 2, &op, sizeof(op));

  if(!nwrite(sd, HEADER_LEN, sendbuf))
  {
    return false;
  }

  if(cmd == JBOD_WRITE_BLOCK)
  {
    if(!nwrite(sd, 256, block))
    {
      return false;
    }
  }

  return true;
}

/* attempts to connect to server and set the global cli_sd variable to the
 * socket; returns true if successful and false if not. */
bool jbod_connect(const char *ip, uint16_t port) {

  cli_sd = socket(AF_INET, SOCK_STREAM, 0);

  if (cli_sd == -1)
  {
    return false;
  }

  caddr.sin_family = AF_INET;
  caddr.sin_port = htons(JBOD_PORT);
  if (inet_aton(JBOD_SERVER, &caddr.sin_addr) == 0)
  {
    return false;
  }

  if (connect(cli_sd, (const struct sockaddr *)&caddr, sizeof(caddr)) == -1)
  {
    return false;
  }
  return true;
}

/* disconnects from the server and resets cli_sd */
void jbod_disconnect(void) {
  close(cli_sd);
  cli_sd = -1;
}

/* sends the JBOD operation to the server and receives and processes the
 * response. */
int jbod_client_operation(uint32_t op, uint8_t *block) {
  uint16_t ret;

  if(send_packet(cli_sd, op, block))
  {
    recv_packet(cli_sd, &op, &ret, block);
    return 0;
  }
  
  return -1;
}
