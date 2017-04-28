/*
 * LeiA.h
 *
 *  Created on: Apr 25, 2017
 *      Author: MoatazFarid
 */

#ifndef LEIA_H_
#define LEIA_H_

/*************************************
 * struct Section
 *************************************/
typedef struct{
    uint16_t     id_msg;    /* 11-bit ID               */
    uint16_t     id_mac;    /* 11-bit ID for MAC       */
    uint16_t     id_fail;   /* 11-bit ID for AUTH Fail */
    uint64_t   kid;       /* 128-bit Key             */
    uint64_t   eid;       /* 56-bit Epoch Counter    */
    uint64_t   keid;      /* 128-bit Temp Key        */
    uint16_t     cid;       /* 16-bit Counter          */
    uint64_t   data;      /* 64-bit Data             */
}tuple_t;

typedef struct{
    uint8_t    is_Extended;
    uint16_t     id;
    uint8_t    command_code;
    uint64_t   eid;
    uint16_t     cid;
    uint64_t   data;
    uint64_t   mac_received;
    uint64_t   mac_computed;
    uint8_t    dlc;
    uint64_t   eid_received;
    uint64_t   eid_mac_received;
    uint64_t   eid_mac_computed;
} message_t;

/*************************************
 *      Functions Defination Section
 *************************************/
void Initiate(void);
void LeiA_Init(void);
void LeiA_SessionKeyGeneration(void);
void DecodeReceivedMessage(void);
uint64_t CalculateMacKeid(void);
uint64_t CalculateEidMac(void);
uint64_t  CalculateMacData(void);
uint8_t ValidateEC(void);
void UpdateEC(void);
void UpdateCounters(void);
uint32_t EncodeExtendedId(uint8_t param_commandcode);
void LeiA_SendAuthMessage(void);
void SendDataMac(void);
void LeiA_HandleAuthFailReceived(void);
void SendEidiMac(void);
void LeiA_HandleEidiMacReceived(void);
void LeiA_HandleDataMacReceived(void);
void LeiA_SendAuthFailMessage(void);
void DecodeReceivedMessage(void);



uint32_t mkExtId(uint32_t id); //used to convert the ID into extended id
uint8_t isExtId(uint32_t id); // used to check if msg is extended or not
uint8_t sendToBus(tCANMsgObject msg); //used to send the can msg to the bus
void msgRecieveHandler(tCANMsgObject msg); // handling the reception of the msg



#endif /* LEIA_H_ */
