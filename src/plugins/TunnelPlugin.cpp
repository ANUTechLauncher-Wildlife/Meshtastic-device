#include "TunnelPlugin.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "RTC.h"
#include "Router.h"
#include "configuration.h"
#include <Arduino.h>

//Master node stuff
#include <WiFi.h>
#include <EEPROM.h>

//SSL
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <arpa/inet.h>
//#include <resolv.h>
#include "openssl/ssl.h"
//#include "openssl/err.h"

#include <assert.h>

#define RXD2 16
#define TXD2 17
#define SERIALPLUGIN_RX_BUFFER 128
#define SERIALPLUGIN_STRING_MAX Constants_DATA_PAYLOAD_LEN
#define SERIALPLUGIN_TIMEOUT 250
#define SERIALPLUGIN_BAUD 38400
#define SERIALPLUGIN_ACK 1

TunnelPlugin *tunnelPlugin;
TunnelPluginRadio *tunnelPluginRadio;

TunnelPlugin::TunnelPlugin() : concurrency::OSThread("TunnelPlugin") {}

char tunnelSerialStringChar[Constants_DATA_PAYLOAD_LEN];

TunnelPluginRadio::TunnelPluginRadio() : SinglePortPlugin("TunnelPluginRadio", PortNum_TUNNEL_APP)
{
    boundChannel = Channels::serialChannel;
}

char* ssid = "iPhone";
char* password = "theCallieMunch156";

//SSL code start
#define FAIL    -1

    //Added the LoadCertificates how in the server-side makes.    
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

SSL_CTX *ctx;
int server;
SSL *ssl;
char buf[1024];
int bytes;
char hostname[]="127.0.0.1";
char portnum[]="5000";
char CertFile[] = "/home/myCA/cacert.pem";
char KeyFile[] = "/home/myCA/private/cakey.pem";

SSL_library_init();

ctx = InitCTX();
LoadCertificates(ctx, CertFile, KeyFile);
server = OpenConnection(hostname, atoi(portnum));
ssl = SSL_new(ctx);      /* create new SSL connection state */
SSL_set_fd(ssl, server);    /* attach the socket descriptor */

//SSL code end
int32_t TunnelPlugin::runOnce()
{
#ifndef NO_ESP32

// //Test sending
    // tunnelPluginRadio->sendPayload();
    // //Create zeroed packet hopefully
    // MeshPacket *p =packetPool.allocZeroed();
    // //p->channel
    // //p->decoded.dest
    // //p->decoded.payload.bytes
    // //p->decoded.payload.size = pb_encode_to_bytes(p->decoded.payload.bytes, sizeof(p->decoded.payload.bytes), fields, &payload);
    // //p->decoded.portnum
    // //p->decoded.request_id
    // //p->decoded.source
    // p->decoded.want_response = false;
    // //p->encrypted.bytes
    // //p->encrypted.size
    // p->from = nodeDB.getNodeNum();
    // p->hop_limit = HOP_RELIABLE; //3
    // p->id = generatePacketId(); //Creates unique packet id
    // p->priority = MeshPacket_Priority_BACKGROUND;
    // //p->rx_rssi
    // //p->rx_snr
    // //TODO: no idea what this is doing
    // p->rx_time = getValidTime(RTCQualityFromNet); // Just in case we process the packet locally - make sure it has a valid timestamp
    
    // //Send to broadcast address (so all nodes will hopefully recieve it)
    // p->to = NODENUM_BROADCAST;
    // //p->want_ack
    // p->which_payloadVariant = MeshPacket_decoded_tag; //assumes payload is decoded at the start?
    // service.sendToMesh(p);
    
    // //NEED TO FREE OR NAH?
    // free(p);
    
    //END TEST CODE

    //EEPROM TEST
    // byte saved_byte = EEPROM.readByte(0);
    // DEBUG_MSG("eeprom after restart saved: %d\n", saved_byte);
    // DEBUG_MSG("WRITING 69 TO EEPROM\n");
    
    // byte test = 'a';
    // EEPROM.begin(0x20);
    // delay(2000); // Some delay
    // EEPROM.put(512, test);
    // EEPROM.commit();

    // DEBUG_MSG("eeprom saved: %d\n", saved_byte);
    // EEPROM.put(512, 3);
    // EEPROM.commit();
    
    //Wifi config test
    //Plain text bad?
    //CONNECTION TO WIFI WORKS
    if (firstTime) {
        DEBUG_MSG("Trying to connect to wifi\n");
        WiFi.begin(ssid, password); // Should probably time out

        if (WiFi.isConnected()) {
            DEBUG_MSG("Connected to wifi\n");
        }   

    }
            
    if (WiFi.isConnected()) {
        DEBUG_MSG("connected to wifi\n");
        
        //Send information to server
        if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
            DEBUG_MSG("Failed to connect via ssl to server\n");
            //ERR_print_errors_fp(stderr);
            
        else
        {   
            //POST REQUEST
            char *tag_id_str = "TagId=";
            char *tag_id = "1"; //Update w actual tag id receieved
            char *tracker_id_str = "&TrackerId=";
            char *tracker_id = "123"; //Update w actual tracker id received
            char *sight_time_str = "&SightingTime=1";
            char *sight_time = "1"; //Update w actual sight time

            char *query_str;  
            query_str = (char*) malloc(strlen(tag_id_str) + strlen(tag_id) + strlen(tracker_id_str) + strlen(tracker_id) + strlen(sight_time_str) + strlen(sight_time));
            strcpy(query_str, tag_id_str);
            strcat(query_str, tag_id);
            strcat(query_str, tracker_id_str);
            strcat(query_str, tracker_id);
            strcat(query_str, sight_time_str;
            strcat(query_str, sight_time);


            char *request_line = "POST /api/Sightings/AnimalSighted HTTP/1.1\r\n";
            char *content_type = "Content-Type: text/plain\r\n";
            char *content_length_str = "Content-Length: ";
            int content_length = strlen(query_str);
            int length = snprintf( NULL, 0, "%d", content_length);
            char* cl_str = (char *) malloc( length + 1 );
            snprintf( cl_str, length + 1, "%d", length );

            char *carrier = "\r\n\r\n";

            //requeust line, headers, body (query)
            char *msg = (char *) malloc(strlen(request_line) + strlen(content_type) + strlen(content_length_str) + strlen(cl_str) + strlen(carrier) /*need to add \r\n to end of this header + \r\n at end of headers*/ + strlen(query_str) + 1 /*null termianted to be safe */);
            strcpy(msg,request_line);
            strcat(msg,content_type);
            strcat(msg,content_length_str);
            strcat(msg,cl_str);
            free(cl_str);
            strcat(msg,carrier);
            strcat(msg,query_str);            

            //Hopefully this works if we can get the arpa/inet.h library to work

            DEBUG_MSG("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);        /* get any certs */
            SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
            bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
            buf[bytes] = 0;
            DEBUG_MSG("Received: \"%s\"\n", buf); //THE MESSAGE BACK SHOULD BE TRUE ON SUCCESSFUL POST

            if (strcmp(buf, "true") != 0) { //If server did not get message
                //Store in eeprom for sending later
            }

            SSL_free(ssl);        /* release connection state */
        }
        close(server);         /* close socket */
        SSL_CTX_free(ctx);        /* release context */


    }
    //Try and reconnect TODO: This probably needs to time out so that main node doesn't get stuck
    else {
        DEBUG_MSG("Trying to reconnect to wifi\n");
        WiFi.begin(ssid, password);
        DEBUG_MSG("Finished trying to reconnect to wifi\n");
    }


    //end wifi config test

    radioConfig.preferences.tunnelplugin_enabled = 1;
    radioConfig.preferences.tunnelplugin_echo_enabled = 1;


    if (radioConfig.preferences.tunnelplugin_enabled) {

        if (firstTime) {
            DEBUG_MSG("Initializing tunnel serial peripheral interface\n");
            Serial1.begin(SERIALPLUGIN_BAUD, SERIAL_8N1, RXD2, TXD2);
            Serial1.setTimeout(SERIALPLUGIN_TIMEOUT);
            Serial1.setRxBufferSize(SERIALPLUGIN_RX_BUFFER);

            tunnelPluginRadio = new TunnelPluginRadio();

            firstTime = 0;

        } else {
            String serialString;

            while (Serial1.available()) {
                serialString = Serial1.readString();
                serialString.toCharArray(tunnelSerialStringChar, Constants_DATA_PAYLOAD_LEN);

                tunnelPluginRadio->sendPayload();

                DEBUG_MSG("Tunnel Reading Recevied: %s\n", tunnelSerialStringChar);
            }
        }

        return (10);
    } else {
        DEBUG_MSG("Tunnel Plugin Disabled\n");

        return (INT32_MAX);
    }
#else
    return INT32_MAX;`
#endif
}

MeshPacket *TunnelPluginRadio::allocReply()
{

    auto reply = allocDataPacket(); // Allocate a packet for sending

    return reply;
}

void TunnelPluginRadio::sendPayload(NodeNum dest, bool wantReplies)
{
    MeshPacket *p = allocReply();
    p->to = dest;
    p->decoded.want_response = wantReplies;

    p->want_ack = SERIALPLUGIN_ACK;

    p->decoded.payload.size = strlen(tunnelSerialStringChar); // You must specify how many bytes are in the reply
    memcpy(p->decoded.payload.bytes, tunnelSerialStringChar, p->decoded.payload.size);

    service.sendToMesh(p);
}

bool TunnelPluginRadio::handleReceived(const MeshPacket &mp)
{
#ifndef NO_ESP32

    if (radioConfig.preferences.tunnelplugin_enabled) {

        auto &p = mp.decoded;
        if (getFrom(&mp) == nodeDB.getNodeNum()) {

            if (radioConfig.preferences.tunnelplugin_echo_enabled) {
                if (lastRxID != mp.id) {
                    lastRxID = mp.id;
                    Serial1.printf("%s", p.payload.bytes);
                }
            }
        }
    } else {
        DEBUG_MSG("Tunnel Plugin Disabled\n");
    }

#endif
    return true; // Let others look at this message also if they want
}
