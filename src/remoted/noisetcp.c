/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "shared.h"
#include "os_net/os_net.h"
#include "remoted.h"

#ifdef NOISESOCKET_ENABLED
#include "virgil-noisesocket.h"

static int process_message() {
#if 0
     /* Receive message  */
        recv_b = recvfrom(logr.sock, buffer, OS_MAXSTR, 0,
                          (struct sockaddr *)&peer_info, &peer_size);

        /* Nothing received */
        if (recv_b <= 0) {
            continue;
        }

        /* Set the source IP */
        satop((struct sockaddr *) &peer_info, srcip, IPSIZE);
        srcip[IPSIZE] = '\0';

        /* Get a valid agent id */
        if (buffer[0] == '!') {
            tmp_msg = buffer;
            tmp_msg++;

            /* We need to make sure that we have a valid id
             * and that we reduce the recv buffer size
             */
            while (isdigit((int)*tmp_msg)) {
                tmp_msg++;
                recv_b--;
            }

            if (*tmp_msg != '!') {
                merror(ENCFORMAT_ERROR, __local_name, srcip);
                continue;
            }

            *tmp_msg = '\0';
            tmp_msg++;
            recv_b -= 2;

            agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);
            if (agentid == -1) {
                if (check_keyupdate()) {
                    agentid = OS_IsAllowedDynamicID(&keys, buffer + 1, srcip);
                    if (agentid == -1) {
                        merror(ENC_IP_ERROR, ARGV0, buffer + 1, srcip);
                        continue;
                    }
                } else {
                    merror(ENC_IP_ERROR, ARGV0, buffer + 1, srcip);
                    continue;
                }
            }
        } else {
            agentid = OS_IsAllowedIP(&keys, srcip);
            if (agentid < 0) {
                if (check_keyupdate()) {
                    agentid = OS_IsAllowedIP(&keys, srcip);
                    if (agentid == -1) {
                        merror(DENYIP_WARN, ARGV0, srcip);
                        continue;
                    }
                } else {
                    merror(DENYIP_WARN, ARGV0, srcip);
                    continue;
                }
            }
            tmp_msg = buffer;
        }

        /* Decrypt the message */
        tmp_msg = ReadSecMSG(&keys, tmp_msg, cleartext_msg,
                             agentid, recv_b - 1);
        if (tmp_msg == NULL) {
            /* If duplicated, a warning was already generated */
            continue;
        }

        /* Check if it is a control message */
        if (IsValidHeader(tmp_msg)) {
            /* We need to save the peerinfo if it is a control msg */
            memcpy(&keys.keyentries[agentid]->peer_info, &peer_info, peer_size);
            keys.keyentries[agentid]->rcvd = time(0);

            save_controlmsg((unsigned)agentid, tmp_msg);

            continue;
        }

        /* Generate srcmsg */
        snprintf(srcmsg, OS_FLSIZE, "(%s) %s", keys.keyentries[agentid]->name,
                 keys.keyentries[agentid]->ip->ip);

        /* If we can't send the message, try to connect to the
         * socket again. If it not exit.
         */
        if (SendMSG(logr.m_queue, tmp_msg, srcmsg,
                    SECURE_MQ) < 0) {
            merror(QUEUE_ERROR, ARGV0, DEFAULTQUEUE, strerror(errno));

            if ((logr.m_queue = StartMQ(DEFAULTQUEUE, WRITE)) < 0) {
                ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQUEUE);
            }
        }
    #endif
    return -1;
}

static void on_client_accepted(vn_serverside_client_t *ctx)
{
    printf("           SERVER: New client is connected %s\n", ctx->ip);
}

static void on_client_disconnected(vn_serverside_client_t *ctx)
{
    printf("           SERVER: Client is disconnected %s\n", ctx->ip);
}

static void on_client_received(vn_serverside_client_t *client, uint8_t *data, size_t data_sz)
{
    data[data_sz] = 0;
    printf("           SERVER: Data received from client %s data: <%s>\n", client->ip, data);
//    process_agent_request((char*)data, authpass, use_ip_address, client->ip, true, client);
}

#endif // NOISESOCKET_ENABLED

/* Handle Noisesocket TCP connections */
void HandleNoisesocketTCP(int port)
{
#ifdef NOISESOCKET_ENABLED
    verbose(NOISE_START_SERVER, ARGV0);
    
    uv_loop_t *uv_loop = NULL;

    const char *addr = "0.0.0.0";

    vn_server_t *server = NULL;

    /* Create UV loops */
    uv_loop = uv_default_loop();

    vn_virgil_credentials_t virgil_credentials;
    memset(&virgil_credentials, 0, sizeof(virgil_credentials));

    /* Start server */
    server = vn_server_new(addr, port,
                           "NOISESOCKET SERVER",
                           virgil_credentials,
                           uv_loop,
                           on_client_accepted,
                           on_client_disconnected,
                           on_client_received);
    vn_server_start(server);
    uv_run(uv_loop, UV_RUN_DEFAULT);

    vn_server_free(server);
    
#else
    verbose(NOISE_IS_NOT_ENABLED, ARGV0);
#endif
}
