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
#include "LeiA.h"

/*************************************
 *      Variables Sections
 *************************************/
const uint8_t DISABLE = 0;
const uint8_t ENABLE  = 1;

volatile uint8_t CanChannel = 0;

tuple_t t;
volatile message_t m_rx;

tCANMsgObject MsgObjectTx; //CAN msg that will be sent
tCANMsgObject msg_received; //CAN msg that will be recieved

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
void initiate(uint8_t canCh){
    CanChannel = canCh;
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
*             Remarks: the actual commandcode is just 2bit
***************************************************************************************************/
uint32_t EncodeExtendedId(uint8_t param_commandcode)
{
    uint32_t      temp_id;
    uint8_t      temp_cc;
    uint16_t       temp_cid;

    temp_cc   = param_commandcode; // the actual commandcode is just 2bit
    temp_cid  = t.cid;
    // id= 00000000000000000000000
    // cid=000000001100101011111010
    // cc =000000110000000000000000
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
    return (id|0x80000000);
}

////////////////////// ToDo //////////////////////////////
/***************************************************************************************************
*       Function name: sendToBus
*         Description: Send the can msg to the bus
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: 1 or 0 indicating send state
*    Global variables: -
*             Remarks: it will use the can base indicated in configuration section
***************************************************************************************************/
uint8_t sendToBus(tCANMsgObject msg){

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
    uint64_t canData ;
    uint8_t *pointerCanToData = (uint8_t *)&canData;


    temp_id  = EncodeExtendedId(0); // the important bits are 18 bits ,command code ==0 means data msg
    temp_id += t.id_msg<<18;
    msg.ui32MsgID = mkExtId(temp_id);
//    msg.dlc = 7;
    msg.ui32MsgLen = 7;
//    msg.pui8MsgData =
    canData = t.data;
    msg.pui8MsgData = (uint8_t *)&canData;
//    output(msg);
    if(1==sendToBus(msg)){ //send data msg to channel
        //preparing the msc msg

        temp_id  = EncodeExtendedId(1);//command code ==0 means mac msg
        temp_id += t.id_mac<<18;
        msg.ui32MsgID= mkExtId(temp_id);

        //if (debug_state == ENABLE) write("Sender: Calculate MAC Data");
        msg.ui32MsgLen = 8;
        canData = CalculateMacData();
        msg.pui8MsgData =(uint8_t *)&canData;
        if(1==sendToBus(msg)){
            //done

        }else{
            // the mac msg wasn't sent
        }
    }else{
        // the data msg wasn't sent
    }
}

/*****************************************************************************/
/* !Description: Handle Resynchronization at Sender Side                     */
/*****************************************************************************/


/***************************************************************************************************
*       Function name: LeiA_HandleAuthFailReceived
*         Description: handle the resynch if the Auth Fail Message Received
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void LeiA_HandleAuthFailReceived(void)
{
//  if (debug_state == ENABLE) write("Sender: Update Counters");
  UpdateCounters();
//  if (debug_state == ENABLE) write("Sender: Send Eidi MAC");
  SendEidiMac();
//  if (debug_state == ENABLE) write("Sender: Calculate Keid");
  t.keid = CalculateMacKeid();//LeiA_SessionKeyGeneration(); BUG
}

/***************************************************************************************************
*       Function name: SendEidiMac
*         Description: send the epoch counter in mac and send the mac
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void SendEidiMac(void)
{
    uint32_t temp_id;
    tCANMsgObject msg;
    uint64_t canData ;
    uint8_t *pointerCanToData = (uint8_t *)&canData;

    temp_id  = EncodeExtendedId(2);
    temp_id += t.id_msg<<18;
    msg.ui32MsgID   = mkExtId(temp_id);
    canData = t.eid;
    msg.pui8MsgData =(uint8_t *)&canData;

    msg.ui32MsgLen = 8;
    if(1==sendToBus(msg)){
        //done
        temp_id  = EncodeExtendedId(3);
        temp_id += t.id_mac<<18;
        msg.ui32MsgID   = mkExtId(temp_id);
//        if (debug_state == ENABLE) write("Sender: Calculate Eid MAC");
        msg.ui32MsgLen = 8;
        canData = CalculateEidMac();
        msg.pui8MsgData =(uint8_t *)&canData;
        if(1==sendToBus(msg)){
            //done

        }else{
            // the mac msg wasn't sent
        }
    }else{
        // the eid data msg wasn't sent
    }

}

/***************************************************************************************************
*       Function name: LeiA_HandleEidiMacReceived
*         Description: handle the reception of the epoch counter
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void LeiA_HandleEidiMacReceived(void)
{
  uint8_t temp_e_c;
  int64 temp_e_mac;

//  if (debug_state == ENABLE) write("Sender: Validate e & c");
  temp_e_c = ValidateEC();

  if (temp_e_c != 0)
  {
//    if (debug_state == ENABLE) write("Sender: Update e & c");
    UpdateEC();
//    if (debug_state == ENABLE) write("Sender: Calculate Keid");
    t.keid = CalculateMacKeid();//LeiA_SessionKeyGeneration(); BUG
//    if (debug_state == ENABLE) write("News - Sender: ReSync Achieved");
  }
  else
  {
//    if (debug_state == ENABLE) write("Sender: Send Auth Fail Message");
    LeiA_SendAuthFailMessage();
  }
}


/*****************************************************************************/
/* !Description: Handle Data/MAC Frames                                      */
/*****************************************************************************/

/***************************************************************************************************
*       Function name: LeiA_HandleDataMacReceived
*         Description: handle the recieved data msg
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void LeiA_HandleDataMacReceived(void)
{
//  if (debug_state == ENABLE) write("Sender: Update Counters");
  UpdateCounters();

  if (m_rx.mac_computed != m_rx.mac_received)
  {
//    if (debug_state == ENABLE) write("Sender: Send Auth Fail Message");
    LeiA_SendAuthFailMessage();
  }
  else
  {
    if (debug_state == ENABLE) write("News - Sender: Normal Message Received");
    /* Normal Message Received */
  }
}

/*****************************************************************************/
/* !Description: Handle Resynchronization at Receiver Side                   */
/*****************************************************************************/
/***************************************************************************************************
*       Function name: LeiA_SendAuthFailMessage
*         Description: send the msg of the Auth  failure
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
void LeiA_SendAuthFailMessage(void)
{
    tCANMsgObject msg;
//    uint64_t canData  = 0;
//    uint8_t *pointerCanToData = (uint8_t *)&canData;
    msg.ui32MsgID = t.id_mac;
    msg.ui32MsgLen = 0;
    sendToBus(msg) //send to bus
}

/***************************************************************************************************
*       Function name: isExtId
*         Description: check if the msg is external or not
*     Parameters (IN): -
*    Parameters (OUT): -
* Parameters (IN/OUT): -
*        Return value: -
*    Global variables: -
*             Remarks: -
***************************************************************************************************/
uint8_t isExtId(uint32_t id)
{
    if(0 != ( (0x80000000 & id)| 0x80000000 ) ){
        return 1;
    }else{
        return 0;
    }
}

// ToDo  Search for Message ID
void DecodeReceivedMessage(void)
{
  int temp_received_id;

    m_rx.is_Extended = isExtId(msg_received.ui32MsgID);

  if (m_rx.is_Extended == 0)
  {
    m_rx.id = msg_received.ui32MsgID;
    if (m_rx.id == 0x102/*t.id_msg*/) /* TBD - Search for Message ID*/
    {
      /* AUTH Fail Message */
      m_rx.id = msg_received.ui32MsgID;
//      if (debug_state == ENABLE) write("Sender: Auth Fail Message Received!");
      LeiA_HandleAuthFailReceived();
    }
  }
  else
  {
    temp_received_id = msg_received.ui32MsgID ; /* Moataz edit valOfId(msg_received);*/
    m_rx.command_code = (temp_received_id & (0x03<<16))>>16;
    m_rx.cid = temp_received_id & (0xffff);
    m_rx.id = (temp_received_id & (0x7ff << 18))>>18;

    switch(m_rx.command_code)
    {

      case 0: /* Data Message */
        if (m_rx.id == 0x200/*t.id_msg*/) /* TBD - Search for Message ID*/
        {
//          if (debug_state == ENABLE) write("Sender: Data Message Received!!");
          m_rx.dlc = msg_received.ui32MsgLen;
          m_rx.data = msg_received.pui8MsgData;
//          if (debug_state == ENABLE) write("Sender: Calculate MAC Data");
          m_rx.mac_computed = CalculateMacData();
        }
      break;

      case 1: /* MAC Message */
        if (m_rx.id == 0x201/*t.id_mac*/) /* TBD - Search for MAC ID*/
        {
//          if (debug_state == ENABLE) write("Sender: MAC for Data Message Received!!");
          m_rx.dlc = msg_received.ui32MsgLen;
          m_rx.mac_received = msg_received.pui8MsgData;
//          if (debug_state == ENABLE) write("Sender: Handle Data & MAC");
          LeiA_HandleDataMacReceived();
        }
      break;

       case 2: /* eidi Message */
        if (m_rx.id == 0x200/*t.id_msg*/) /* TBD - Search for Message ID*/
        {
//          if (debug_state == ENABLE) write("Sender: eidi Message Received");
          m_rx.dlc = msg_received.ui32MsgLen;
          m_rx.eid_received = msg_received.pui8MsgData;
//          if (debug_state == ENABLE) write("Sender: Calculate Eidi MAC");
          m_rx.eid_mac_computed = CalculateEidMac();
        }
      break;

      case 3: /* eidi_MAC Message */
        if (m_rx.id == 0x201/*t.id_mac*/) /* TBD - Search for MAC ID*/
        {
//          if (debug_state == ENABLE) write("Sender: MAC for eidi Message Received");
          m_rx.dlc = msg_received.ui32MsgLen;
          m_rx.eid_mac_received = msg_received.pui8MsgData;
//          if (debug_state == ENABLE) write("Sender: Handle MAC for eidi");
          LeiA_HandleEidiMacReceived();
        }
      break;

      default:
//        if (debug_state == ENABLE) write("Sender: Update Counters");
        UpdateCounters();
      break;
    }
  }
}

void msgRecieveHandler(tCANMsgObject msg){
    msg_received = msg;
    DecodeReceivedMessage();
}
