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

char* ssid = "test_network";
char* password = "password";

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
    
    //Wifi config test
    //Plain text bad?
    //CONNECTION TO WIFI WORKS
    if (firstTime) {
        DEBUG_MSG("Trying to connect to wifi\n");
        WiFi.begin(ssid, password);
        DEBUG_MSG("Finished trying to connect to wifi\n");
        
        //EEPROM TEST
        byte saved_byte = EEPROM.readByte(0);
        DEBUG_MSG("eeprom after restart saved: %d\n", saved_byte);
        DEBUG_MSG("WRITING 69 TO EEPROM\n");
        
        byte test = 'a';
        EEPROM.begin(0x20);
        delay(2000); // Some delay
        EEPROM.put(512, test);
        EEPROM.commit();
        
    }
    
    byte saved_byte = EEPROM.readByte(512);
    
    DEBUG_MSG("eeprom saved: %d\n", saved_byte);
    EEPROM.put(512, 3);
    EEPROM.commit();
    
    //Try to receive message
    
        //Save it to eeprom maybe with sent counter
        
        //eeprom has 512 bytes of memory
        
    if (WiFi.isConnected()) {
        DEBUG_MSG("connected to wifi\n");
        
        //Send eprom messages and increment counter​
        //If counter is > 3 or whatever
            //Delete from eeprom        
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
