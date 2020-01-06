__cloudflaredd__ is a small script meant to run as a systemd process to automatically upload dynamic dns changes to a set of domain dns records managed by [Cloudflare](https://www.cloudflare.com/). Essentially, every three minutes, we use a protocol named STUN (defined in [RFC 5389](https://tools.ietf.org/html/rfc5389)) to retrieve our public ip address. If the address changed from the previous iteration, we update cloudflare records with new data. Using STUN is great because it's super fast (a single UDP-based round trip) and totally free because Google hosts free public STUN servers, which are typically used within the ICE protocol for nat traversal (which is heavily used in Google's WebRTC framework).

## Installation & Setup

The project is meant to run as a `systemctl` service in the background, and thus is super lightweight. It's implemented as a single C file with a dependency on [libcurl](https://curl.haxx.se/libcurl/). To download and build the project, simply do the following:
```
git clone git@github.com:MorganGallant/cloudflaredd.git
cd cloudflaredd
make
```

__Before building__, you will want to edit the static array defined on L253 of `cloudflaredd.c`. Here, you can enter in all of your specific credentials and dns records that you want to update whenever a change of ip occurs. These are the defaults, which will not work:
```
static cf_dns_record_t cf_target_dns_records[] = {
    {.identifer = NULL,
     .name = "your-cool-domain.com",
     .type = "A",
     .zone = "zone-id-goes-here",
     .api_token = "your-api-token-goes-here",
     .proxied = false}};
```
For example, if you wanted to edit the `test.morgangallant.com` A record, and the proxied `dev.morgangallant.com` A record, the structure should look like the following: (`identifier` can be NULL if you do not know the DNS Record ID)
```
static cf_dns_record_t cf_target_dns_records[] = {
    {
        .identifer = NULL,
        .name = "test.morgangallant.com",
        .type = "A",
        .zone = "zone-id-goes-here",
        .api_token = "your-api-token-goes-here",
        .proxied = false
    },
    {
        .identifer = NULL,
        .name = "dev.morgangallant.com",
        .type = "A",
        .zone = "zone-id-goes-here",
        .api_token = "your-api-token-goes-here",
        .proxied = true
    }
    };
```

If it would benefit people, I'd gladly improve on the configuration aspect of cloudflaredd. Perhaps a .toml file or .yml file to describe the configuration, rather than having to compile it in. Let me know!

## Support / Future Features

As always, feel free to submit issues / pull requests to better the codebase. This is a small project that I needed to do for my tower, since my apartment doesn't have a static ip address. If you want to get in contact, send me an [email](mailto:morgan@morgangallant.com)!
