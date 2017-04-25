/***************************************************************************************************
*                             Moataz Farid All rights reserved
****************************************************************************************************
*                    File: LeiA.c
*             Description: Lightweight Authentication Protocol for CAN
*      Platform Dependent: yes
*                   Notes: this library Uses Tiva-c driverlib/can.h driver
***************************************************************************************************/
/*************************************
 * Includes Section
 *************************************/

#include <stdint.h>
#include "driverlib/can.h"

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
uint64_t EncodeExtendedId(uint8_t param_commandcode);
void LeiA_SendAuthMessage(void);
void SendDataMac(void);
void LeiA_HandleAuthFailReceived(void);
void SendEidiMac(void);
void LeiA_HandleEidiMacReceived(void);
void LeiA_HandleDataMacReceived(void);
void LeiA_SendAuthFailMessage(void);
void DecodeReceivedMessage(void);

uint32_t mkExtId(uint32_t id); //used to convert the ID into extended id

/*************************************
 *      Variables Sections
 *************************************/
const uint8_t DISABLE = 0;
const uint8_t ENABLE  = 1;

struct tuple_t t;
struct message_t m_rx;

tCANMsgObject MsgObjectTx; //CAN msg that will be sent

volatile uint64_t mac_calculated_till_mac;


/*************************************
 *      Functions Section
 *************************************/

/***************************************************************************************************
*       Function name: initiate
*         Description: Authentication Protocol initialization
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: This Function should be called after the ECU is POwered ON to enable the protocol
***************************************************************************************************/
void initiate(void){

    LeiA_Init();
    LeiA_SessionKeyGeneration();
}


/***************************************************************************************************
*       Function name: LeiA_Init
*         Description: Authentication Protocol init function that reset the variables of the tuple_t
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
// Todo: make the msg ID a variable that can be changed from configuration when using the library
void LeiA_Init(void){
    t.id_msg    = 0x100; /* msg ID */
    t.id_mac    = 0x101; /* id of MAC */
    t.id_fail   = 0x102; /* id of AUTH Fail */
    t.kid       = 10; /* 128 bit key */
    t.eid       = 0; /* 56 Epoch Counter*/
    t.keid      = 0; /* 128 Temp key*/
    t.cid       = 0; /* 16 counter*/
    t.data      = 0x55; /* 64 data */
}


/***************************************************************************************************
*       Function name: CalculateMacKeid
*         Description: calculate the temp key which is sum of 128bit key and epoch counter
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: uint64_t MAC Temp key
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
uint64_t CalculateMacKeid(void){
    uint64_t temp_mac;
    // sum of the temp key and epock counter
    temp_mac = t.kid + t.eid;
    return temp_mac;
}

/***************************************************************************************************
*       Function name: CalculateEidMac
*         Description: calculate epock counter
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: uint64_t MAC epock counter
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
uint64_t CalculateEidMac(void)
{
    uint64_t temp_mac;
    // epoch is the sum of this node tempkey + the recieved msg counter + the recieved msg epock counter
    temp_mac = t.keid + m_rx.cid + m_rx.eid_received;
    return temp_mac;
}


/***************************************************************************************************
*       Function name: CalculateEidMac
*         Description: calculate epock counter
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: uint64_t mac data
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
uint64_t  CalculateMacData(void)
{
    uint64_t temp_mac;
    //MAC data is sum of temp key + counter + data
    temp_mac = t.keid + t.cid + t.data;
    return temp_mac;
}

/***************************************************************************************************
*       Function name: ValidateEC
*         Description: validate the epock counters and counters are sync
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: uint8_t 1 or 0
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
uint8_t ValidateEC(void)
{
    // check that the recieved epock id is greater than that ECU epock id
    if(m_rx.eid_received > t.eid)
    {
        return 1;
    }// check that the received epock counter is the same as that ECU epock counter
    //and the received counter is greater than  ECU counter
    else if ((m_rx.eid_received == t.eid) && (m_rx.cid > t.cid))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}


/***************************************************************************************************
*       Function name: UpdateEC
*         Description: update the epock counter and normal counter with the recieved epock/normal
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void UpdateEC(void)
{
  t.eid = m_rx.eid_received;
  t.cid = m_rx.cid;
}


/*****************************************************************************/
/* !Description: Supporting Functions                                        */
/*****************************************************************************/


/***************************************************************************************************
*       Function name: UpdateCounters
*         Description: update the epock counter and normal counter with the recieved epock/normal
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void UpdateCounters(void)
{
  if (t.cid == 0xffff)// if the counter will overflow
  {
    if (t.eid == 0xffffffff)// if the epock counter will overflow
    {
      t.eid = 0; //reset epock counter
    }
    else// the epock still can count more
    {
      t.eid++; // increase  epock counter
    }

    t.cid = 0; // reset the counter (if)/not the epock reseted

    // calculate the new temp key since the epock changed
    t.keid = CalculateMacKeid();
  }
  else // incase the counter won't overflow
  {
    t.cid++; // increase the counter
  }
}

/***************************************************************************************************
*       Function name: EncodeExtendedId
*         Description: encode the command code and the counter inside the extended id
*     Parameters (IN): param_commandcode
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: uint32_t EncodedExtendedID
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
uint32_t EncodeExtendedId(uint8_t param_commandcode)
{
    uint32_t      temp_id;
    uint8_t      temp_cc;
    uint16_t       temp_cid;

    temp_cc   = param_commandcode;
    temp_cid  = t.cid;
    // id= 00000000000000000000000
    // cid=000000001100101011111010
    // cc =101010110000000000000000
    temp_id = t.cid + (temp_cc<<16);
    return temp_id;
}

/***************************************************************************************************
*       Function name: mkExtId
*         Description: used to convert the ID into extended id by setting the Most significant bit 1
*     Parameters (IN): uint32_t id
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: uint32_t
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
uint32_t mkExtId(uint32_t id){
    return (id|0x80000000)
}

/*****************************************************************************/
/* !Description: Session Key Generation                                      */
/*****************************************************************************/
/***************************************************************************************************
*       Function name: LeiA_SessionKeyGeneration
*         Description: Generate a new session key
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void LeiA_SessionKeyGeneration(void){
    // increase the Epoch Counter
    t.eid++;
    // generate the Mac Temp key
    t.keid = CalculateMacKeid();
    // reset the counter
    t.cid = 0;
}

/*****************************************************************************/
/* !Description: Send Authentication Message                                 */
/*****************************************************************************/
/***************************************************************************************************
*       Function name: LeiA_SendAuthMessage
*         Description: start sending the Auth message
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void LeiA_SendAuthMessage(void)
{
//  if (debug_state == ENABLE) write("Sender: Update Counters");
    //update the counters
    UpdateCounters();

//  if (debug_state == ENABLE) write("Sender: Send Data & MAC");
    //send MAC Data
    SendDataMac();
}

/***************************************************************************************************
*       Function name: SendDataMac
*         Description: prepare and send mac data
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void SendDataMac(void)
{
    uint32_t temp_id; //PS:converted from 64bit to 32bit
    tCANMsgObject msg;

    temp_id  = EncodeExtendedId(0); // encode
    temp_id += t.id_msg<<18;
    msg.ui32MsgID = mkExtId(temp_id);
    //  msg.id   = mkExtId(temp_id);
    msg.dlc = 7;
    msg.int64(0) = t.data;
    output(msg);
    //write("Data Message with ID %lx and Extended ID %lx",t.id_msg,msg.id);

    temp_id  = EncodeExtendedId(1);
    temp_id += t.id_mac<<18;
    msg.id   = mkExtId(temp_id);

    //if (debug_state == ENABLE) write("Sender: Calculate MAC Data");
    msg.dlc = 8;
    msg.int64(0) = CalculateMacData();
    output(msg);
}
