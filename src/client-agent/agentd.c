/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "os_net/os_net.h"

#ifdef NOISESOCKET_ENABLED
#include <uv.h>
#include <virgil-noisesocket.h>

int send_msg_noise(vn_client_t *client, const char *msg);
void run_notify_noise(vn_client_t *client);

static void on_session_ready(uv_tcp_t *handle, ns_result_t result)
{
    if (NS_OK != result) {
        printf("Session cannot be established !\n");
        return;
    }

    printf("\n--------------- Connection over Noisesocket is READY ------------------\n");

    vn_client_t *client = 0;
    ns_get_ctx(handle->data, USER_CTX_0, (void**)&client);

    start_agent_send(client, 1);
}

static int process_msg(vn_serverside_client_t *client, char *buffer, int recv_b)
{
    unsigned int attempts = 0, g_attempts = 1;

    char *tmp_msg;
    char msg[OS_MAXSTR + 2];
    char cleartext[OS_MAXSTR + 1];
    char fmsg[OS_MAXSTR + 1];

    memset(msg, '\0', OS_MAXSTR + 2);
    memset(cleartext, '\0', OS_MAXSTR + 1);
    memset(fmsg, '\0', OS_MAXSTR + 1);
    snprintf(msg, OS_MAXSTR, "%s%s", CONTROL_HEADER, HC_STARTUP);

    /* Id of zero -- only one key allowed */
    tmp_msg = ReadSecMSG(&keys, buffer, cleartext, 0, recv_b - 1);
    if (tmp_msg == NULL) {
        merror(MSG_ERROR, ARGV0, agt->rip[agt->rip_id]);
        return -1;
    }

    /* Check for commands */
    if (IsValidHeader(tmp_msg)) {
        /* If it is an ack reply */
        if (strcmp(tmp_msg, HC_ACK) == 0) {
            available_server = time(0);

            verbose(AG_CONNECTED, ARGV0, agt->rip[agt->rip_id],
                    agt->port);

//            if (is_startup) {
                /* Send log message about start up */
                snprintf(msg, OS_MAXSTR, OS_AG_STARTED,
                        keys.keyentries[0]->name,
                        keys.keyentries[0]->ip->ip);
                snprintf(fmsg, OS_MAXSTR, "%c:%s:%s", LOCALFILE_MQ,
                        "ossec", msg);
                send_msg_noise(client, fmsg);
//            }
            return 0;
        }
    }

    return 0;
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t* buf)
{
    if (nread <= 0) {
        printf("Read error !\n");
        return;
    }

    printf("Received: %d\n", (int)nread);

    vn_client_t *client = 0;
    ns_get_ctx(stream->data, USER_CTX_0, (void**)&client);

    process_msg(client, buf->base, nread);
    
    run_notify_noise(client);
}

static int start_noisesocket_agent(const char *identity, const char *password) {
    vn_client_t *client;
    uv_loop_t *uv_loop = NULL;

    // Create UV loops
    uv_loop = uv_default_loop();

    client = vn_client_new(identity, password, uv_loop);

    vn_client_connect(client,
                  agt->rip[0], // server_addr
                  atoi(agt->port),
                  on_session_ready,
                  on_read);

    uv_run(uv_loop, UV_RUN_DEFAULT);

    vn_client_free(client);

    return 0;
}

#endif

/* Start the agent daemon */
void AgentdStart(const char *dir, int uid, int gid, const char *user, const char *group, int use_noisesocket)
{
    int rc = 0;
    int maxfd = 0;
    fd_set fdset;
    struct timeval fdtimeout;

    available_server = 0;

    /* Initial random numbers must happen before chroot */
    srandom_init();

    /* Going Daemon */
    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Set group ID */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* chroot */
    if (Privsep_Chroot(dir) < 0) {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }
    nowChroot();

    if (Privsep_SetUser(uid) < 0) {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* Create the queue and read from it. Exit if fails. */
    if ((agt->m_queue = StartMQ(DEFAULTQUEUE, READ)) < 0) {
        ErrorExit(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));
    }

    maxfd = agt->m_queue;
    agt->sock = -1;

    /* Create PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror(PID_ERROR, ARGV0);
    }

    /* Read private keys  */
    verbose(ENC_READ, ARGV0);

    OS_ReadKeys(&keys);
    OS_StartCounter(&keys);

    os_write_agent_info(keys.keyentries[0]->name, NULL, keys.keyentries[0]->id,
                        agt->profile);

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    random();

    /* Connect UDP */
    rc = 0;
    while (rc < agt->rip_id) {
        verbose("%s: INFO: Server %d: %s", ARGV0, rc+1, agt->rip[rc]);
        rc++;
    }

    /* Connect to server using Noisesocket*/
    if (use_noisesocket) {
        /* Hack for the Demo*/
        char lhostname[512];
        memset(lhostname, 0, sizeof(lhostname));
        gethostname(lhostname, 512 - 1);

        agt->rip_id = 0;

        start_noisesocket_agent(lhostname, lhostname);

        return;
    }

    /* Try to connect to the server */
    if (!connect_server(0)) {
        ErrorExit(UNABLE_CONN, ARGV0);
    }

    /* Set max fd for select */
    if (agt->sock > maxfd) {
        maxfd = agt->sock;
    }

    /* Connect to the execd queue */
    if (agt->execdq == 0) {
        if ((agt->execdq = StartMQ(EXECQUEUE, WRITE)) < 0) {
            merror("%s: INFO: Unable to connect to the active response "
                   "queue (disabled).", ARGV0);
            agt->execdq = -1;
        }
    }

    /* Try to connect to server */
    os_setwait();

    start_agent(1);

    os_delwait();

    /* Send integrity message for agent configs */
    intcheck_file(OSSECCONF, dir);
    intcheck_file(OSSEC_DEFINES, dir);

    /* Send first notification */
    run_notify();

    /* Maxfd must be higher socket +1 */
    maxfd++;

    /* Monitor loop */
    while (1) {
        /* Monitor all available sockets from here */
        FD_ZERO(&fdset);
        FD_SET(agt->sock, &fdset);
        FD_SET(agt->m_queue, &fdset);

        fdtimeout.tv_sec = 1;
        fdtimeout.tv_usec = 0;

        /* Continuously send notifications */
        run_notify();

        /* Wait with a timeout for any descriptor */
        rc = select(maxfd, &fdset, NULL, NULL, &fdtimeout);
        if (rc == -1) {
            ErrorExit(SELECT_ERROR, ARGV0, errno, strerror(errno));
        } else if (rc == 0) {
            continue;
        }

        /* For the receiver */
        if (FD_ISSET(agt->sock, &fdset)) {
            receive_msg();
        }

        /* For the forwarder */
        if (FD_ISSET(agt->m_queue, &fdset)) {
            EventForward();
        }
    }
}

