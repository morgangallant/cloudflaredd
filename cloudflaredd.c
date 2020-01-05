/*
 * Copyright (c) 2020 Morgan Gallant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <arpa/inet.h>
#include <assert.h>
#include <curl/curl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
    freeaddrinfo(results);
    return NULL;
  }

  freeaddrinfo(results);
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
static void stun_client_cleanup(stun_client_t **client) {
  if (!(*client))
    return;
  close((*client)->fd);
  free(*client);
  *client = NULL;
}

// The address of the public Google-hosted stun server to use.
#define GOOGLE_STUN_ADDR "stun.l.google.com:19302"

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
  stun_client_cleanup(&client);
  return pub_ip;
}

/* Cloudflare API Implementation */

typedef struct {
  char *identifer;
  char *name;
  char *type;
  char *zone;
  char *api_token;
  bool proxied;
} cf_dns_record_t;

// The set of dns records to update with our new public address.
static cf_dns_record_t cf_target_dns_records[] = {
    {.identifer = NULL,
     .name = "your-cool-domain.com",
     .type = "A",
     .zone = "zone-id-goes-here",
     .api_token = "your-api-token-goes-here",
     .proxied = false}};

// Construct a query url for retrieving an identifier from a dns record.
static char *cf_construct_query_url(cf_dns_record_t *rec) {
  size_t url_len = strlen(rec->name) + strlen(rec->type) + strlen(rec->zone);
  url_len += 68;
  char *url = malloc((url_len + 1) * sizeof(char)); // null terminator + 1
  snprintf(url, url_len,
           "https://api.cloudflare.com/client/v4/zones/%s/"
           "dns_records?type=%s&name=%s",
           rec->zone, rec->type, rec->name);
  url[url_len] = '\0';
  return url;
}

// Construct an authorization token header string for the cloudflare request.
static char *cf_construct_auth_token(const cf_dns_record_t *rec) {
  size_t token_len = 23 + strlen(rec->api_token);
  char *token = malloc((token_len + 1) * sizeof(char));
  snprintf(token, token_len, "Authorization: Bearer %s", rec->api_token);
  token[token_len] = '\0';
  return token;
}

typedef struct {
  char *data;
  size_t len;
} cf_message_t;

// Initialize a cf_message_t to default values.
static cf_message_t *cf_message_init() {
  cf_message_t *resp = malloc(sizeof(cf_message_t));
  resp->data = strdup("");
  resp->len = 0;
  return resp;
}

// Cleans up any allocated memory from a cf_message_t.
static void cf_message_cleanup(cf_message_t **msg) {
  if (!(*msg))
    return;
  if ((*msg)->data)
    free((*msg)->data);
  free(*msg);
  *msg = NULL;
}

// CURL callback function for storing response in cf_message_t object.
// Credit: https://curl.haxx.se/libcurl/c/postinmemory.html
static size_t cf_mem_write_cb(void *resp, size_t size, size_t nmemb, void *up) {
  size_t real_size = size * nmemb;
  cf_message_t *resp_buf = (cf_message_t *)up;

  resp_buf->data = realloc(resp_buf->data, resp_buf->len + real_size + 1);
  assert(resp_buf->data != NULL);

  memcpy(&(resp_buf->data[resp_buf->len]), resp, real_size);
  resp_buf->len += real_size;
  resp_buf->data[resp_buf->len] = '\0';
  return real_size;
}

// Configures a cloudflare api request with libcurl.
static CURL *cf_setup_request(const char *url, const cf_dns_record_t *record,
                              cf_message_t *dest) {
  CURL *curl = curl_easy_init();
  if (!curl)
    return NULL;

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cf_mem_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)dest);

  return curl;
}

// Update a dns record structure with its identifier.
static bool cf_get_identifier(cf_dns_record_t *record) {
  bool ret_val = false;

  // Fast path, we already have an identifier for this record.
  if (record->identifer != NULL && strlen(record->identifer) != 0)
    return true;

  char *url = cf_construct_query_url(record);
  char *token = cf_construct_auth_token(record);
  cf_message_t *resp = cf_message_init();

  CURL *curl;
  CURLcode res;
  struct curl_slist *headers = NULL;

  curl = cf_setup_request(url, record, resp);
  if (!curl)
    goto cleanup;

  headers = curl_slist_append(headers, token);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    goto cleanup;

  record->identifer = malloc(33 * sizeof(char));
  memcpy(record->identifer, resp->data + 18, 32);

  ret_val = true;

cleanup:
  if (url)
    free(url);
  if (token)
    free(token);
  if (resp)
    cf_message_cleanup(&resp);
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);
  return ret_val;
}

// A compile-time constant macro for finding the size of an array.
#define ARRAY_LEN(arr) (sizeof(arr) / sizeof(arr[0]))

// Fill all the identifiers for an array of dns records.
static bool cf_fill_identifiers(cf_dns_record_t *records, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    bool res = cf_get_identifier(&records[i]);
    if (!res)
      return false;
  }
  return true;
}

static char *cf_format_up_url(const cf_dns_record_t *record) {
  // Sanity check.
  if (!record->identifer)
    return NULL;

  size_t len = strlen(record->zone) + strlen(record->identifer);
  len += 57;
  char *buffer = malloc((len + 1) * sizeof(char));
  snprintf(buffer, len,
           "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s",
           record->zone, record->identifer);
  buffer[len] = '\0';
  return buffer;
}

// A macro to easily format a boolean as a string.
#define BOOL_STR(x) ((x) ? "true" : "false")

// Creates a request json object to update an existing dns record.xx
static char *cf_format_up_req(const cf_dns_record_t *rec, const char *content) {
  const char *p = BOOL_STR(rec->proxied);
  size_t len =
      strlen(rec->type) + strlen(rec->name) + strlen(content) + strlen(p);
  len += 54;
  char *msg = malloc((len + 1) * sizeof(char));
  snprintf(msg, len,
           "{\"type\":\"%s\",\"name\":\"%s\",\"content\":\"%s\",\"ttl\":1,"
           "\"proxied\":%s}",
           rec->type, rec->name, content, p);
  msg[len] = '\0';
  return msg;
}

// Updates the contents of a cloudflare dns record with new content.
static bool cf_update_content(const cf_dns_record_t *record,
                              const char *content) {
  bool ret_val = false;

  char *url = cf_format_up_url(record);
  char *req_data = cf_format_up_req(record, content);
  char *token = cf_construct_auth_token(record);
  cf_message_t *resp = cf_message_init();

  CURL *curl;
  CURLcode res;
  struct curl_slist *headers = NULL;

  curl = cf_setup_request(url, record, resp);
  if (!curl)
    goto cleanup;

  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, token);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req_data);
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");

  res = curl_easy_perform(curl);
  if (res != CURLE_OK)
    goto cleanup;

  ret_val = true;

cleanup:
  if (url)
    free(url);
  if (req_data)
    free(req_data);
  if (token)
    free(token);
  if (resp)
    cf_message_cleanup(&resp);
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);
  return ret_val;
}

// Updates all the cloudflare records with new content.
static bool cf_update_all(cf_dns_record_t *records, size_t count,
                          const char *content) {
  for (int i = 0; i < count; ++i) {
    bool res = cf_update_content(&records[i], content);
    if (!res) {
      return false;
    }
  }
  return true;
}

// Check if this computers public address changed.
static bool pub_ip_did_change(char *prev_ip) {
  char *curr_ip = stun_get_pub_ip(GOOGLE_STUN_ADDR);
  if (strcmp(prev_ip, curr_ip) == 0)
    return false;

  strcpy(prev_ip, curr_ip);
  free(curr_ip);
  return true;
}

int main() {
  curl_global_init(CURL_GLOBAL_ALL);
  srand(time(NULL));

  char public_addr[INET_ADDRSTRLEN] = {'\0'};
  while (true) {
    if (pub_ip_did_change(public_addr)) {
      size_t num_records = ARRAY_LEN(cf_target_dns_records);
      bool res = cf_fill_identifiers(cf_target_dns_records, num_records);
      if (!res) {
        printf("Failed to fill identifiers for target dns records.\n");
        break;
      }
      res = cf_update_all(cf_target_dns_records, num_records, public_addr);
      if (!res) {
        printf("Failed to update dns records with new content.");
        break;
      }
      printf("Updated records for new IP: %s.\n", public_addr);
    }
    sleep(180); // 180 seconds = 3 mins
  }

  // Makes valgrind happy
  for (int i = 0; i < ARRAY_LEN(cf_target_dns_records); ++i)
    if (cf_target_dns_records[i].identifer)
      free(cf_target_dns_records[i].identifer);

  curl_global_cleanup();
}
