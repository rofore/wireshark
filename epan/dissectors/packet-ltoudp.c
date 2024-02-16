/* Basic LocalTalk over UDP (LToUDP) dissector */
/* For more informations about LToUDP, see
 * https://windswept.home.blog/2019/12/10/localtalk-over-udp/ */
/* This dissector is based upon
 * https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html */

#include <epan/etypes.h>
#include <epan/packet.h>

#include "config.h"

#define LTOUDP_PORT 1954

static int proto_ltoudp = -1;

static int hf_sender_id = -1;
static gint ett_foo = -1;
static dissector_handle_t llap_handle;

static int dissect_ltoudp(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *tree _U_,
                          void *data _U_)
{
    tvbuff_t *next_tvb;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ltoudp");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_ltoudp, tvb, 0, -1, ENC_BIG_ENDIAN);
    proto_tree *ltoudp_tree = proto_item_add_subtree(ti, ett_foo);
    proto_tree_add_item(ltoudp_tree, hf_sender_id, tvb, 0, 4, ENC_BIG_ENDIAN);

    next_tvb = tvb_new_subset_remaining(tvb, 4);
    call_dissector(llap_handle, next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

void proto_register_ltoudp(void)
{
    static hf_register_info hf[] = {
        {
            &hf_sender_id,
            {
                "Sender ID",
                "ltoudp.senderId",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x00,
                NULL,
                HFILL
            }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {&ett_foo};

    proto_ltoudp = proto_register_protocol(
        "LocalTalk over UDP", /* name */
        "LToUDP",			 /* short_name  */
        "ltoudp"				 /* filter_name */
    );

    proto_register_field_array(proto_ltoudp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_ltoudp(void)
{
    static dissector_handle_t ltoudp_handle;

    ltoudp_handle = create_dissector_handle(dissect_ltoudp, proto_ltoudp);
    llap_handle = find_dissector_add_dependency("llap", proto_ltoudp);

    dissector_add_uint("udp.port", LTOUDP_PORT, ltoudp_handle);
}
