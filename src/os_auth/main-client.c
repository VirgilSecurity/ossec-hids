/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#include <errno.h>
#include <string.h>
#include "shared.h"
#include "check_cert.h"

#ifdef NOISESOCKET_ENABLED
#include <uv.h>
#include <virgil-noisesocket.h>
#endif

/* Return codes */
#define RES_OK                      (0)
#define RES_REGISTRATION_ERROR      (-1)
#define RES_PASSWORD_ERROR          (-2)
#define RES_PARSE_ERROR             (-3)
#define RES_WRITE_ERROR             (-4)
#define RES_KEY_SAVE_ERROR          (-5)

#define BUF_SZ                      (2048)


static char *authpass = NULL;
static const char *agentname = NULL;
static int use_noisesocket = 0;

#ifndef NOISESOCKET_ENABLED
#define NOISESOCKET_ENABLED
#endif

#if !defined(LIBOPENSSL_ENABLED) && !defined(NOISESOCKET_ENABLED)

int main()
{
    printf("ERROR: Not compiled. Missing OpenSSL support.\n");
    exit(0);
}

#else

#include <openssl/ssl.h>
#include <uv-unix.h>
#include "auth.h"

static void help_agent_auth(void) __attribute__((noreturn));

/* Print help statement */
static void help_agent_auth()
{
    print_header();
    print_out("  %s: -[VhdtN] [-g group] [-D dir] [-m IP address] [-p port] [-A name] [-c ciphers] [-v path] [-x path] [-k path]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -N          Use Noisesocket");
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out("    -m <addr>   Manager IP address");
    print_out("    -p <port>   Manager port (default: %s)", DEFAULT_PORT);
    print_out("    -A <name>   Agent name (default: hostname)");
    print_out("    -c          SSL cipher list (default: %s)", DEFAULT_CIPHERS);
    print_out("    -v <path>   Full path to CA certificate used to verify the server");
    print_out("    -x <path>   Full path to agent certificate");
    print_out("    -k <path>   Full path to agent key");
    print_out("    -P <path>   Authorization password file [default: /var/ossec/etc/authd.pass");
    print_out(" ");
    exit(1);
}

static int write_server(int use_noisesocket, void *ctx, const void *buf, int num)
{
    if (!use_noisesocket) {
        return SSL_write((SSL*)ctx, buf, num);
    } else {
        if (VN_OK == vn_client_send(ctx, (const uint8_t*)buf, num)) {
            return RES_OK;
        }
    }

    return RES_WRITE_ERROR;
}

static int send_registration_request(int use_noisesocket, void *ctx, const char *authpass, const char *agentname) {
    char buf[BUF_SZ];
    int ret;

    printf("INFO: Using agent name as: %s\n", agentname);

    memset(buf, 0, sizeof(buf));
    if (authpass) {
        snprintf(buf, BUF_SZ, "OSSEC PASS: %s OSSEC A:'%s'\n", authpass, agentname);
    }
    else {
        snprintf(buf, BUF_SZ, "OSSEC A:'%s'\n", agentname);
    }

    ret = write_server(use_noisesocket, ctx, buf, strlen(buf));
    if (ret < 0) {
        printf("SSL write error (unable to send message.)\n");
        ERR_print_errors_fp(stderr);
        return RES_WRITE_ERROR;
    }

    return RES_OK;
}

static int process_response(char *data, int data_sz, void *noisesocket) {
    data[data_sz] = '\0';
    if (strncmp(data, "ERROR", 5) == 0) {
        char *tmpstr;
        tmpstr = strchr(data, '\n');
        if (tmpstr) {
            *tmpstr = '\0';
        }
        printf("%s (from manager)\n", data);
    } else if (strncmp(data, "OSSEC K:'", 9) == 0) {
        char *key;
        char *card_id;
        char *tmpstr;
        char **entry;
        printf("INFO: Received response with agent key\n");

        key = data;
        key += 9;
        tmpstr = strchr(key, '\'');
        if (!tmpstr) {
            printf("ERROR: Invalid key received. Closing connection.\n");
            return RES_PARSE_ERROR;
        }
        *tmpstr = '\0';
        card_id = tmpstr + 2;
        entry = OS_StrBreak(' ', key, 4);
        if (!OS_IsValidID(entry[0]) || !OS_IsValidName(entry[1]) ||
                !OS_IsValidName(entry[2]) || !OS_IsValidName(entry[3])) {
            printf("ERROR: Invalid key received (2). Closing connection.\n");
            return RES_PARSE_ERROR;
        }

        if (use_noisesocket) {
            // Search for Card ID
            if (0 != strncmp(card_id, "OSSEC CARD:'", 12)) {
                return RES_PARSE_ERROR;
            }
            card_id += 12;
            tmpstr = strchr(card_id, '\'');
            if (!tmpstr) {
                printf("ERROR: Invalid Card ID received. Closing connection.\n");
                return RES_PARSE_ERROR;
            }
            *tmpstr = '\0';

            // Save Card ID
            vn_client_t *client;
            client = vn_client_from_socket((uv_tcp_t*)noisesocket);
            if (VN_OK != vn_client_save_card_id(client, card_id)) {
                printf("ERROR: Cannot save Card ID. Closing connection.\n");
                return RES_KEY_SAVE_ERROR;
            }
        }

        {
            FILE *fp;
            fp = fopen(KEYSFILE_PATH, "w");
            if (!fp) {
                printf("ERROR: Unable to open key file: %s", KEYSFILE_PATH);
                return RES_KEY_SAVE_ERROR;
            }
            fprintf(fp, "%s\n", key);
            fclose(fp);
        }
        printf("INFO: Valid key created. Finished.\n");
    }
    return RES_OK;
}

void client_reg_result_cb(vn_client_t *ctx, vn_result_t result) {
    printf("INFO: Registration result %s\n", VN_OK == result ? "OK" : "ERROR");

    if (RES_OK != send_registration_request(true, ctx, authpass, agentname)) {
        exit(1);
    }

    printf("INFO: Send request to manager. Waiting for reply.\n");
}

#ifdef NOISESOCKET_ENABLED

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    buf->base[nread] = 0;
    printf("CLIENT: New data: %s\n", buf->base);

    process_response(buf->base, nread, stream);

    vn_client_disconnect(vn_client_from_socket((uv_tcp_t*)stream), NULL);
}

static int noisesocket_client(const char *addr, int port, const char *identity, const char *password, const char *dir)
{
    /* Do we need to use tickets ? */
    vn_ticket_t ticket;

    vn_client_t *client;
    uv_loop_t *uv_loop = NULL;

    // Create UV loops
    uv_loop = uv_default_loop();

    vn_storage_set_path(dir);

    client = vn_client_new(identity, password, uv_loop);
    vn_client_register(client,
            addr, port,
            &ticket,
            client_reg_result_cb,
            on_read);

    uv_run(uv_loop, UV_RUN_DEFAULT);

    vn_client_free(client);

    return RES_OK;
}

#endif //NOISESOCKET_ENABLED

int main(int argc, char **argv)
{
    int key_added = 0;
    int c;
    int test_config = 0;
    int authenticate = 0;
#ifndef WIN32
    gid_t gid = 0;
#endif

    int sock = 0, portnum, ret = 0;
    char *port = DEFAULT_PORT;
    char *ciphers = DEFAULT_CIPHERS;
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *manager = NULL;
    const char *agent_cert = NULL;
    const char *agent_key = NULL;
    const char *ca_cert = NULL;
    char lhostname[512 + 1];
    char buf[4096 + 1];
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    bio_err = 0;
    buf[4096] = '\0';

#ifdef WIN32
    WSADATA wsaData;
#endif

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "NVdhtg:m:p:A:c:v:x:k:D:P:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_agent_auth();
                break;
            case 'd':
                nowDebug();
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                group = optarg;
                break;
            case 'D':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument", ARGV0);
                }
                dir = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            case 'N':
                use_noisesocket = 1;
                break;
            case 'm':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                manager = optarg;
                break;
            case 'A':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                agentname = optarg;
                break;
            case 'p':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                portnum = atoi(optarg);
                if (portnum <= 0 || portnum >= 65536) {
                    ErrorExit("%s: Invalid port: %s", ARGV0, optarg);
                }
                port = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                ciphers = optarg;
                break;
            case 'v':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                ca_cert = optarg;
                break;
            case 'x':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                agent_cert = optarg;
                break;
            case 'k':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                agent_key = optarg;
                break;
            case 'P':
                if (!optarg) {
                    ErrorExit("%s: -%c needs an argument", ARGV0, c);
                }
                authpass = optarg;
                authenticate++;
                break;
            default:
                help_agent_auth();
                break;
        }
    }

    /* Start daemon */
    debug1(STARTED_MSG, ARGV0);

#ifndef WIN32
    /* Check if the user/group given are valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, "", group);
    }

    /* Exit here if test config is set */
    if (test_config) {
        exit(0);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* Signal manipulation */
    StartSIG(ARGV0);

    /* Create PID files */
    if (CreatePID(ARGV0, getpid()) < 0) {
        ErrorExit(PID_ERROR, ARGV0);
    }
#else
    /* Initialize Windows socket stuff */
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
        ErrorExit("%s: WSAStartup() failed", ARGV0);
    }
#endif /* WIN32 */

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    if (agentname == NULL) {
        lhostname[512] = '\0';
        if (gethostname(lhostname, 512 - 1) != 0) {
            merror("%s: ERROR: Unable to extract hostname. Custom agent name not set.", ARGV0);
            exit(1);
        }
        agentname = lhostname;
    }

    if(authpass == NULL) {
        authpass = AUTHDPASS_PATH;
    }

    if (!manager) {
        merror("%s: ERROR: Manager IP not set.", ARGV0);
        exit(1);
    }

    /* Checking if there is a custom password file */
    if (authpass != NULL && authenticate > 0) {
        FILE *fp;
        fp = fopen(authpass, "r");
        if(!fp) {
            fprintf(stderr, "Cannot open %s: %s\n", authpass, strerror(errno));
            exit(1);
        }
        buf[0] = '\0';

        if (fp) {
            buf[4096] = '\0';
            fgets(buf, 4095, fp);

            if (strlen(buf) > 2) {
                authpass = strndup(buf, 32);
                if(!authpass) {
                    fprintf(stderr, "Could not set the authpass: %s", strerror(errno));
                    exit(1);
                }
            }

            fclose(fp);
            printf("INFO: Using specified password.\n");
        }
    }
    if (!authpass) {
        printf("WARN: No authentication password provided. Insecure mode started.\n");
    }

    /* Start Noisesocket */
    if (use_noisesocket) {
        ret = noisesocket_client(manager, portnum, agentname, agentname, dir);
        exit(ret);
    }

    /* Start SSL */
    ctx = os_ssl_keys(0, dir, ciphers, agent_cert, agent_key, ca_cert);
    if (!ctx) {
        merror("%s: ERROR: SSL error. Exiting.", ARGV0);
        exit(1);
    }

    /* Connect via TCP */
    sock = OS_ConnectTCP(port, manager);
    if (sock <= 0) {
        merror("%s: Unable to connect to %s:%s", ARGV0, manager, port);
        exit(1);
    }

    /* Connect the SSL socket */
    ssl = SSL_new(ctx);
    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    ret = SSL_connect(ssl);
    if (ret <= 0) {
        ERR_print_errors_fp(stderr);
        merror("%s: ERROR: SSL error (%d). Exiting.", ARGV0, ret);
        exit(1);
    }

    printf("INFO: Connected to %s:%s\n", manager, port);

    /* Additional verification of the manager's certificate if a hostname
     * rather than an IP address is given on the command line. Could change
     * this to do the additional validation on IP addresses as well if needed.
     */
    if (ca_cert) {
        printf("INFO: Verifying manager's certificate\n");
        if (check_x509_cert(ssl, manager) != VERIFY_TRUE) {
            debug1("%s: DEBUG: Unable to verify server certificate.", ARGV0);
            exit(1);
        }
    }

    if (RES_OK != send_registration_request(use_noisesocket, ssl, authpass, agentname)) {
        exit(1);
    }

    printf("INFO: Send request to manager. Waiting for reply.\n");

    while (1) {
        ret = SSL_read(ssl, buf, sizeof(buf) - 1);
        switch (SSL_get_error(ssl, ret)) {
            case SSL_ERROR_NONE:

                if (RES_OK != process_response(buf, ret, 0)) {
                    exit(1);
                }
                key_added = 1;

                break;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
                if (key_added == 0) {
                    printf("ERROR: Unable to create key. Either wrong password or connection not accepted by the manager.\n");
                }
                printf("INFO: Connection closed.\n");
                exit(0);
                break;
            default:
                printf("ERROR: SSL read (unable to receive message)\n");
                exit(1);
                break;
        }

    }

    /* Shut down the socket */
    if (key_added == 0) {
        printf("ERROR: Unable to create key. Either wrong password or connection not accepted by the manager.\n");
    }
    SSL_CTX_free(ctx);
    close(sock);

    exit(0);
}

#endif /* LIBOPENSSL_ENABLED */
