/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.net.module.util.dhcp6;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.nio.ByteBuffer;

/**
 * DHCPv6 REPLY packet class, a server sends an Reply message containing assigned leases
 * and configuration parameters in response to a Solicit, Request, Renew or Rebind messages
 * received from a client.
 *
 * https://tools.ietf.org/html/rfc8415#page-24
 */
public class Dhcp6ReplyPacket extends Dhcp6Packet {
    /**
     * Generates a reply packet with the specified parameters including IA_PD and IA_NA.
     */
    Dhcp6ReplyPacket(int transId, @NonNull final byte[] clientDuid,
            @NonNull final byte[] serverDuid, @Nullable final byte[] iapd,
            @Nullable final byte[] iana, boolean rapidCommit) {
        super(transId, 0 /* elapsedTime */, clientDuid, serverDuid, iapd, iana);
        mRapidCommit = rapidCommit;
    }

    /**
     * Generates a reply packet with the specified parameters (IA_PD only).
     */
    Dhcp6ReplyPacket(int transId, @NonNull final byte[] clientDuid,
            @NonNull final byte[] serverDuid, final byte[] iapd, boolean rapidCommit) {
        this(transId, clientDuid, serverDuid, iapd, null /* iana */, rapidCommit);
    }

    /**
     * Return the DHCPv6 REPLY message type (7).
     */
    public byte getMessageType() {
        return DHCP6_MESSAGE_TYPE_REPLY;
    }

    /**
     * Build a DHCPv6 Reply message with the specific parameters.
     */
    public ByteBuffer buildPacket() {
        final ByteBuffer packet = ByteBuffer.allocate(DHCP_MAX_LENGTH);
        final int msgTypeAndTransId = (DHCP6_MESSAGE_TYPE_REPLY << 24) | mTransId;
        packet.putInt(msgTypeAndTransId);

        addTlv(packet, DHCP6_CLIENT_IDENTIFIER, mClientDuid);
        addTlv(packet, DHCP6_SERVER_IDENTIFIER, mServerDuid);
        if (mIaPd != null) {
            addTlv(packet, DHCP6_IA_PD, mIaPd);
        }
        if (mIaNa != null) {
            addTlv(packet, DHCP6_IA_NA, mIaNa);
        }
        if (mRapidCommit) {
            addTlv(packet, DHCP6_RAPID_COMMIT);
        }
        addDnsServersOption(packet, mDnsServers);
        addDomainListOption(packet, mDomainList);

        packet.flip();
        return packet;
    }
}
