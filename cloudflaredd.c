#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* STUN Implementation */

typedef struct {
  char *addr;
  int port;
} stun_addr_t;

// Parses an address into a stun_addr_t structure.
static stun_addr_t *stun_addr_create(const char *address) {
  char *offset = strstr(address, ":");
  if (!offset)
    return NULL;

  stun_addr_t *resp_addr = malloc(sizeof(stun_addr_t));
  assert(resp_addr != NULL);

  // Copy the address without the port number to the return structure.
  long addr_len = offset - address;
  resp_addr->addr = malloc(addr_len * sizeof(char) + 1);
  memcpy(resp_addr->addr, address, addr_len);
  resp_addr->addr[addr_len] = '\0';

  // Parse the port number.
  char *ptr;
  resp_addr->port = (int)strtol(offset + 1, &ptr, 10);
  assert(*ptr == '\0');

  return resp_addr;
}

// Cleanup a stun_addr_t structure.
static void stun_addr_free(stun_addr_t **addr) {
  if (!(*addr))
    return;
  free((*addr)->addr);
  free(*addr);
  *addr = NULL;
}

typedef struct {
  uint16_t type;
  uint16_t size;
  uint32_t cookie;
  uint32_t transaction_id[3];
} stun_message_header_t;

typedef struct {
  int fd;
  struct sockaddr_in localaddr;
  struct sockaddr_in remoteaddr;
  stun_message_header_t req; // we need to store req to verify trans id
} stun_client_t;

// Initialize a socket address structure.
static void init_sockaddr(struct sockaddr_in *a, struct in_addr dst, int p) {
  memset(a, 0, sizeof(*a));
  a->sin_family = AF_INET;
  a->sin_addr = dst;
  a->sin_port = htons(p);
}

// Initialize a stun client for a given server address.
static stun_client_t *stun_client_create(const stun_addr_t *address) {
  // Resolve the remote address.
  struct addrinfo *results = NULL;
  struct addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  int32_t res = getaddrinfo(address->addr, NULL, &hints, &results);
  if (res != 0)
    return NULL;

  struct in_addr stunaddr;
  if (results)
    stunaddr = ((struct sockaddr_in *)results->ai_addr)->sin_addr;
  else
    return NULL;

  stun_client_t *resp = malloc(sizeof(stun_client_t));
  init_sockaddr(&resp->remoteaddr, stunaddr, address->port);
  const struct in_addr localdst = {.s_addr = INADDR_ANY};
  init_sockaddr(&resp->localaddr, localdst, 0);

  // Bind the socket to the local address before returning.
  resp->fd = socket(AF_INET, SOCK_DGRAM, 0);
  res = bind(resp->fd, (struct sockaddr *)&resp->localaddr,
             sizeof(resp->localaddr));
  if (res != 0) {
    free(resp);
    return NULL;
  }

  return resp;
}

// Defined in RFC 5389, must be passed with all requests.
static uint32_t stun_magic_cookie = 0x2112A442;

// Send the request to the stun server.
static bool stun_client_send_request(stun_client_t *client) {
  client->req.type = htons(0x0001);              // binding request
  client->req.size = htons(0x0000);              // request size
  client->req.cookie = htonl(stun_magic_cookie); // magic cookie
  for (int i = 0; i < 3; ++i)
    client->req.transaction_id[i] = rand(); // random transaction id

  ssize_t res = sendto(client->fd, &client->req, sizeof(client->req), 0,
                       (struct sockaddr *)&client->remoteaddr,
                       sizeof(client->remoteaddr));
  if (res < 0)
    return false;

  // Set timeout for the request and indicate success.
  struct timeval timeout = {/*secs=*/5, 0};
  setsockopt(client->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  return true;
}

typedef struct {
  uint16_t type;
  uint16_t size;
} stun_attribute_header_t;

typedef struct {
  uint8_t reserved;
  uint8_t family;
  uint16_t port;
  uint32_t address;
} stun_xor_mapped_addr_t;

// Defined in RFC 5389, used to check the response message type.
static uint16_t stun_binding_response_type = 0x0101;

// Defined in RFC 5389, used to scan for the address response attribute.
static uint16_t stun_xor_mapped_addr_type = 0x0020;

// Read the response from the stun server and decode our public address.
static char *stun_client_read_response(stun_client_t *client) {
  char buffer[1 << 12];
  ssize_t response_size = read(client->fd, buffer, sizeof(buffer));
  if (response_size < 0)
    return NULL;

  // Ensure that the response was valid by checking type and transaction id.
  char *ptr = buffer;
  stun_message_header_t *header = (stun_message_header_t *)ptr;
  if (header->type != htons(stun_binding_response_type))
    return NULL;
  for (int i = 0; i < 3; ++i)
    if (header->transaction_id[i] != client->req.transaction_id[i])
      return NULL;

  // Parse the body of the response once we verified that it is right type.
  ptr += sizeof(stun_message_header_t);
  while (ptr < buffer + response_size) {
    stun_attribute_header_t *att_header = (stun_attribute_header_t *)ptr;
    if (att_header->type == htons(stun_xor_mapped_addr_type)) {
      ptr += sizeof(stun_attribute_header_t);
      stun_xor_mapped_addr_t *addr = (stun_xor_mapped_addr_t *)ptr;

      // Decode the address using the magic cookie and return.
      uint32_t public_addr = htonl(addr->address) ^ stun_magic_cookie;
      char *resp_buffer = malloc(INET_ADDRSTRLEN * sizeof(char));
      int l =
          snprintf(resp_buffer, INET_ADDRSTRLEN - 1, "%d.%d.%d.%d",
                   ((public_addr >> 24) & 0xFF), ((public_addr >> 16) & 0xFF),
                   ((public_addr >> 8) & 0xFF), (public_addr & 0xFF));
      resp_buffer[l] = '\0';
      return resp_buffer;
    }
    ptr += sizeof(stun_attribute_header_t) + att_header->size;
  }
  return NULL;
}

// Cleanup the stun client by closing the bound socket.
static void stun_client_cleanup(stun_client_t *client) { close(client->fd); }

// Get the public ip address of this server.
static char *stun_get_pub_ip(const char *stun_server_addr) {
  stun_addr_t *addr = stun_addr_create(stun_server_addr);
  stun_client_t *client = stun_client_create(addr);

  char *pub_ip = NULL;

  bool res = stun_client_send_request(client);
  if (!res)
    goto done;

  pub_ip = stun_client_read_response(client);

done:
  stun_addr_free(&addr);
  stun_client_cleanup(client);
  return pub_ip;
}

// The address of the public Google-hosted stun server to use.
#define GOOGLE_STUN_ADDR "stun.l.google.com:19302"

int main() {
  const char *ip = stun_get_pub_ip(GOOGLE_STUN_ADDR);
  printf("IP: %s\n", ip);
  return 0;
}