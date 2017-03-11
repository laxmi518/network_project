/** Echo client. */
/** Usage: ./client -c50 -o2 -h10000 127.0.0.1 **/ 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>

#include <arpa/inet.h>

#include <pthread.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h>



#define PORT "5000" // the port client will be connecting to 

#define MAXDATASIZE (100) // max number of bytes we can get at once 

#if !defined(BIND_SOURCE_PORT)
# define BIND_SOURCE_PORT (0)
#endif

#if !defined(SERVER_CLOSE)
# define SERVER_CLOSE (0)
#endif

int g_nloop;
int g_nhello;
int g_noverwrap;
int g_resolve;
int success;
long g_restimes[1000001];

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

const char *host;
const char *port;

SSL_CTX *ctx;
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

struct addrinfo* getaddr()
{
    struct addrinfo hints, *servinfo;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return NULL;
    }

    return servinfo;
}

void prepare(int sock)
{
    //int yes=1;

    //setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

#if BIND_SOURCE_PORT
    {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_port = htons(20000);
        bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    }
#endif
}



void shutdown_ssl(SSL *ssl)
{
    int r=SSL_shutdown(ssl);
    switch(r){
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        printf("Shutdown failed\n");
    }
}

int done(SSL *ssl)
{
    SSL_free(ssl);
    // free(request);
    return(0);
}

print_ssl_error(const SSL *ssl, int sslerr)
{
     int rc = SSL_get_error(ssl,sslerr);
     switch(rc){
        case SSL_ERROR_NONE:
            printf("SSL_ERROR_NONE\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("SSL_ERROR_ZERO_RETURN\n");
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            printf("SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE\n");
            break;
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
            printf("SSL_ERROR_WANT_CONNECT,SSL_ERROR_WANT_ACCEPT\n");
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("SSL_ERROR_WANT_X509_LOOKUP\n");
            break;        
        case SSL_ERROR_SYSCALL:
            printf("SSL_ERROR_SYSCALL\n");
            perror("perror:");
            break;
        case SSL_ERROR_SSL:
            printf("SSL_ERROR_SSL\n");
            break;
        default:
            printf("default\n");
            break;
     }
}
void* do_connect(struct addrinfo *servinfo)
{
    int r;
    struct addrinfo *p, *pinfo;
    int sockfd, numbytes;  
    char buf[MAXDATASIZE];
    int *socks = NULL;
    SSL **ssls = NULL;
    int i, j, k;
    struct timespec t1, t2;

    sleep(1);

    socks = malloc(sizeof(int)*g_noverwrap);
    ssls = (SSL *)malloc(sizeof(SSL *)*g_noverwrap);
    memset(socks, 0, sizeof(int)*g_noverwrap);

    pthread_mutex_lock(&g_mutex);
    pthread_mutex_unlock(&g_mutex);
    success = 0;
    for (i = 0; i < g_nloop; ++i) {
        // loop through all the results and connect to the first we can
        if (servinfo) {
            pinfo = servinfo;
        } else {
            pinfo = getaddr();
        }
        p = pinfo;
        k = 0;
        for (k=0; k<g_noverwrap; ++k) {
            for (; p != NULL; p = p->ai_next) {
                if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
                    perror("client: socket");
                    continue;
                }
                prepare(sockfd);
                if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
                    close(sockfd);
                    perror("client: connect");
                    continue;
                }
                socks[k] = sockfd;
                /* Connect the SSL socket */
                SSL *ssl=SSL_new(ctx);
                printf("after SSL_new\n");
                BIO *sbio =BIO_new_socket(sockfd,BIO_NOCLOSE);
                printf("after BIO_new_socket\n");
                SSL_set_bio(ssl,sbio,sbio);
                int rc = SSL_connect(ssl);
                printf("after ssl_connect\n");
                if(rc<=0)
                {
                    printf("SSL connect error\n");
                    print_ssl_error(ssl,rc);
                }
                ssls[k] = ssl;
                break;
            }
            if (!p) break;
        }

        if (p == NULL) {
            continue;
        }
        for (j=0; j<g_nhello; ++j) {
        clock_gettime(CLOCK_MONOTONIC, &t1);

            for (k=0; k<g_noverwrap; ++k) {
                sockfd = socks[k];
                // send(sockfd, "hello\n", 6, 0);
                r=SSL_write(ssls[k],"hello\n",6);
                printf("after ssl_write\n");
                switch(SSL_get_error(ssls[k],r)){      
                    case SSL_ERROR_NONE:
                    if(r!=r)
                        printf("Incomplete write!\n");
                    break;
                    default:
                        printf("SSL write problem\n");
                }
                // send(sockfd, "hello\n", 6, 0);
            }
            for (k=0; k<g_noverwrap; ++k) {
                sockfd = socks[k];
                // if ((numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0)) < 0) {
                //     perror("recv");
                //     close(sockfd);
                //     goto exit;
                // }
                // if (numbytes != 6) {
                //     printf("Recieved %d bytes\n", numbytes);
                //     goto exit;
                // }
                char buf[100];
                r=SSL_read(ssls[k],buf,100);
                int len;
                switch(SSL_get_error(ssls[k],r)){
                    case SSL_ERROR_NONE:
                    len=r;
                    break;
                    case SSL_ERROR_ZERO_RETURN:
                        shutdown_ssl(ssls[k]);
                    case SSL_ERROR_SYSCALL:
                        fprintf(stderr,
                        "SSL Error: Premature close\n");
                        done(ssls[k]);
                        // return NULL;
                    default:
                        printf("SSL read problem\n");
                }

                printf("buf: %s\n",buf);
    
                __sync_fetch_and_add(&success, 1);
            }
        {
            clock_gettime(CLOCK_MONOTONIC, &t2);
            long long t = t2.tv_sec * 1000000000LL + t2.tv_nsec;
            t          -= t1.tv_sec * 1000000000LL + t1.tv_nsec;
            t /= 10000; // ns => 10us
            if (t > 1000000) t=1000000;
            __sync_fetch_and_add(g_restimes+t, 1);
        }
        }

#if SERVER_CLOSE
        do {
            numbytes = recv(sockfd, buf, MAXDATASIZE-1, 0);
        } while (numbytes > 0);
#endif

        for (k=0; k<g_noverwrap; ++k) {
            close(socks[k]);
        }
        if (!servinfo) {
            freeaddrinfo(pinfo);
        }
    }
exit:
    free(socks);
    return NULL;

}

void show_restime_res(int start, int stop, int step)
{
    int i;
    for (i = start; i < stop; i += step) {
        long sum = 0;
        int j;
        for (j = 0; j < step; ++j) sum += g_restimes[i+j];
        if (sum > 0) {
            if (start < 99) {
                printf(" <%5d [us]: %ld\n", (i+step)*10, sum);
            } else {
                printf(" <%5d [ms]: %ld\n", (i+step)/100, sum);
            }
        }
    }
}

void show_restimes()
{
    show_restime_res(0, 10, 1);
    show_restime_res(10, 100, 10);
    show_restime_res(100, 1000, 100);
    show_restime_res(1000, 10000, 1000);
    show_restime_res(10000, 100000, 10000);
    show_restime_res(100000, 1000000, 100000);
    printf(" >= 10sec: %ld\n", g_restimes[1000000]);
}

SSL_CTX *initialize_ctx(char *crtfile,char *keyfile)
  {
    BIO *bio_err=0;
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    
    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();
      
      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }
    
    /* Create our context*/
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    printf("crtfile = %s\n",crtfile);
    if(!(SSL_CTX_use_certificate_file(ctx, crtfile,SSL_FILETYPE_PEM )))
      printf("Can't read certificate file\n");

    // pass=password;
    // SSL_CTX_set_default_passwd_cb(ctx,
    //   password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx,
      keyfile,SSL_FILETYPE_PEM)))
      printf("Can't read key file\n");

    /* Load the CAs we trust*/
//     if(!(SSL_CTX_load_verify_locations(ctx,
//       CA_LIST,0)))
//       berr_exit("Can't read CA list");
// #if (OPENSSL_VERSION_NUMBER < 0x00905100L)
//     SSL_CTX_set_verify_depth(ctx,1);
// #endif
    
    return ctx;
  }
int main(int argc, char *argv[])
{
    ctx=initialize_ctx("./certificate.crt", "./privateKey.key");
    struct addrinfo *servinfo;
    int rv;
    int opt;

    int verbose = 0;
    int nthread = 1;
    g_nloop = 1;
    g_nhello = 100;
    g_noverwrap = 1;

    port = PORT;
    host = NULL;

    while (-1 != (opt = getopt(argc, argv, "n:h:c:p:o:vg"))) {
        switch (opt) {
        case 'n':
            g_nloop = atoi(optarg);
            break;
        case 'h':
            g_nhello = atoi(optarg);
            break;
        case 'c':
            nthread = atoi(optarg);
            break;
        case 'p':
            port = optarg;
            break;
        case 'o':
            g_noverwrap = atoi(optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'g':
            g_resolve = 1;
            break;
        default:
            fprintf(stderr, "Unknown option: %c\n", opt);
            return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "usage: client [-vg] [-n connect count] [-h hellos per connec] [-c threads] [-p port] hostname\n");
        return 2;
    }
    host = argv[optind];

    servinfo = NULL;
    if (!g_resolve) {
        servinfo = getaddr();
        if (servinfo == NULL) {
            fprintf(stderr, "Can't resolve %s:%s\n", host, port);
            return 3;
        }
    }

    pthread_mutex_lock(&g_mutex);
    long long time_consumed;
    {
        struct timespec t1, t2;
        void* res;
        pthread_t *threads = malloc(sizeof(pthread_t)*nthread);
        int i;
        for (i = 0; i < nthread; ++i) {
            rv = pthread_create(&threads[i], NULL, (void*)do_connect, (void*)servinfo);
            if (rv == -1) {
                perror("Failed to create thread");
                return 3;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pthread_mutex_unlock(&g_mutex);

        for (i = 0; i < nthread; ++i) {
            rv = pthread_join(threads[i], &res);
            if (rv == -1) {
                perror("Failed to join a thread.");
                return 4;
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        time_consumed  = t2.tv_sec * 1000000000LL + t2.tv_nsec;
        time_consumed -= t1.tv_sec * 1000000000LL + t1.tv_nsec;
        free(threads);
    }

    freeaddrinfo(servinfo); // all done with this structure
    if (verbose)
        show_restimes();

    printf("Throughput: %.2lf [#/sec]\n",
            (success)*1000000000.0/(time_consumed));

    return 0;
}

