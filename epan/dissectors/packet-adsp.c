
#include <epan/etypes.h>
#include <epan/packet.h>

#include "config.h"
#include "packet-atalk.h"

#define ADSP_DESCRIPTOR_OFFSET 12

static int proto_adsp = -1;
static gint ett_foo = -1;


static int hf_srcconid = -1;

static int hf_adspdesc = -1;
static int hf_msg_type = -1;
static int hf_bit_attention = -1;
static int hf_bit_eom = -1;
static int hf_bit_ackreq = -1;
static int hf_bit_control = -1;


static int hf_data_firstbyteseq = -1;
static int hf_data_nextrecvseq = -1;
static int hf_data_recvwindow = -1;

static int hf_cntl_firstbyteseq = -1;
static int hf_cntl_nextrecvseq = -1;
static int hf_cntl_recvwindow = -1;

static int hf_attn_sendseq = -1;
static int hf_attn_recvseq = -1;
static int hf_attn_recvwindow = -1;

static const value_string msg_type_vals[] = {
    { 0, "Probe or Acknowledgment" },
    { 1, "Open Connection Request" },
    { 2, "Open Connection Acknowledgment" },
    { 3, "Open Connection Request and Acknowledgment" },
    { 4, "Open Connection Denial" },
    { 5, "Close Connection Advice" },
    { 6, "Forward Reset" },
    { 7, "Forward Reset Acknowledgment" },
    { 8, "Retransmit Advice" },
    { 0, NULL }
};



typedef enum ADSP_PacketType_TAG {
    ADSP_PACKET_TYPE_DATA = 0,
    ADSP_PACKET_TYPE_CONTROL = 1 << 7,
    ADSP_PACKET_TYPE_ATTENTION = 1 << 4
} ADSP_PacketType_t;

static int dissect_adsp(tvbuff_t *tvb,
                        packet_info *pinfo,
                        proto_tree *tree _U_,
                        void *data _U_)
{
    uint8_t adspDescriptor = tvb_get_uint8(tvb, ADSP_DESCRIPTOR_OFFSET);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ADSP");

    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_adsp, tvb, 0, -1, ENC_BIG_ENDIAN);
    proto_tree *adsp_tree = proto_item_add_subtree(ti, ett_foo);

    proto_tree_add_item(adsp_tree, hf_srcconid, tvb, 0, 2, ENC_BIG_ENDIAN);

    if (adspDescriptor & ADSP_PACKET_TYPE_CONTROL) {
        col_add_str(pinfo->cinfo, COL_INFO, "Control Packet");
        switch (adspDescriptor & 0x0F) {
            case 0: col_add_str(pinfo->cinfo, COL_INFO, "Probe or Acknowledgment"); break;
            case 1: col_add_str(pinfo->cinfo, COL_INFO, "Open Connection Request"); break;
            case 2: col_add_str(pinfo->cinfo, COL_INFO, "Open Connection Acknowledgment"); break;
            case 3: col_add_str(pinfo->cinfo, COL_INFO, "Open Connection Request and Acknowledgment"); break;
            case 4: col_add_str(pinfo->cinfo, COL_INFO, "Open Connection Denial"); break;
            case 5: col_add_str(pinfo->cinfo, COL_INFO, "Close Connection Advice"); break;
            case 6: col_add_str(pinfo->cinfo, COL_INFO, "Forward Reset"); break;
            case 7: col_add_str(pinfo->cinfo, COL_INFO, "Forward Reset Acknowledgment"); break;
            case 8: col_add_str(pinfo->cinfo, COL_INFO, "Retransmit Advice"); break;
            default: col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Control Packet (Code %d)", adspDescriptor & 0x0F); break;
        }

        proto_tree_add_item(adsp_tree, hf_cntl_firstbyteseq, tvb, 2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(adsp_tree, hf_cntl_nextrecvseq, tvb, 6, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(adsp_tree, hf_cntl_recvwindow, tvb, 10, 2, ENC_BIG_ENDIAN);
    } else if (adspDescriptor & ADSP_PACKET_TYPE_ATTENTION) {
        col_add_str(pinfo->cinfo, COL_INFO, "Attention Packet");
        proto_tree_add_item(adsp_tree, hf_attn_sendseq, tvb, 2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(adsp_tree, hf_attn_recvseq, tvb, 6, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(adsp_tree, hf_attn_recvwindow, tvb, 10, 2, ENC_BIG_ENDIAN);
    } else {
        col_add_str(pinfo->cinfo, COL_INFO, "Data Packet");
        proto_tree_add_item(adsp_tree, hf_data_firstbyteseq, tvb, 2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(adsp_tree, hf_data_nextrecvseq, tvb, 6, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(adsp_tree, hf_data_recvwindow, tvb, 10, 2, ENC_BIG_ENDIAN);
    }

    proto_tree_add_item(adsp_tree, hf_adspdesc,     tvb, ADSP_DESCRIPTOR_OFFSET, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(adsp_tree, hf_msg_type,     tvb, ADSP_DESCRIPTOR_OFFSET, 1, ENC_NA);
    proto_tree_add_item(adsp_tree, hf_bit_attention,tvb, ADSP_DESCRIPTOR_OFFSET, 1, ENC_NA);
    proto_tree_add_item(adsp_tree, hf_bit_eom,      tvb, ADSP_DESCRIPTOR_OFFSET, 1, ENC_NA);
    proto_tree_add_item(adsp_tree, hf_bit_ackreq,   tvb, ADSP_DESCRIPTOR_OFFSET, 1, ENC_NA);
    proto_tree_add_item(adsp_tree, hf_bit_control,  tvb, ADSP_DESCRIPTOR_OFFSET, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

void proto_register_adsp(void)
{
    static hf_register_info hf[] = {
        {
            &hf_srcconid,
            {
                "Source Connection ID",
                "adsp.conid.src",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_adspdesc,
            {
                "ADSP Descriptor",
                "adsp.descriptor",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_data_firstbyteseq,
            {
                "First Byte Sequence Number",
                "adsp.data.firstbyteseq",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_data_nextrecvseq,
            {
                "Next Receive Sequence Number",
                "adsp.data.nextrecvseq",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_data_recvwindow,
            {
                "Receive Window Size",
                "adsp.data.recvwindow",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_cntl_firstbyteseq,
            {
                "First Byte Sequence Number",
                "adsp.cntl.firstbyteseq",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_cntl_nextrecvseq,
            {
                "Next Receive Sequence Number",
                "adsp.cntl.nextrecvseq",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_cntl_recvwindow,
            {
                "Receive Window Size",
                "adsp.cntl.recvwindow",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        },
        {
            &hf_attn_sendseq,
            {
                "Attention Send Sequence Number",
                "adsp.attn.sendseq",
                FT_UINT32,
                BASE_DEC,
                NULL, 0x00, NULL, HFILL
            }
        },
        {
            &hf_attn_recvseq, {
                "Attention Receive Sequence Number",
                "adsp.attn.recvseq",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
            }
        },
        // Lower nibble enum
        { &hf_msg_type,
            { "Control Code", "adsp.cntlcode",
                FT_UINT8, BASE_DEC,
                VALS(msg_type_vals), 0x0F,
                NULL, HFILL }
        },

        // Upper nibble flags
        { &hf_bit_attention,
            { "Attention Bit", "adsp.attention",
                FT_BOOLEAN, 8,
                NULL, 1 << 4,
                NULL, HFILL }
        },

        { &hf_bit_eom,
            { "EOM Bit", "adsp.eom",
                FT_BOOLEAN, 8,
                NULL, 1 << 5,
                NULL, HFILL }
        },

        { &hf_bit_ackreq,
            { "ACK Request Bit", "adsp.ackreq",
                FT_BOOLEAN, 8,
                NULL, 1 << 6,
                NULL, HFILL }
        },

        { &hf_bit_control,
            { "Control Bit", "adsp.control",
                FT_BOOLEAN, 8,
                NULL, 1 << 7,
                NULL, HFILL }
        },


    };

    /* Setup protocol subtree array */
    static gint *ett[] = {&ett_foo};

    proto_adsp = proto_register_protocol(
                                         "AppleTalk Data Stream Protocol",   /* Name */
                                         "ADSP",                             /* Short Name  */
                                         "adsp"                              /* Filter Name */
                                         );

    proto_register_field_array(proto_adsp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_adsp(void)
{
    static dissector_handle_t adsp_handle;

    adsp_handle = create_dissector_handle(dissect_adsp, proto_adsp);

    dissector_add_uint("ddp.type", DDP_ADSP, adsp_handle);
}
