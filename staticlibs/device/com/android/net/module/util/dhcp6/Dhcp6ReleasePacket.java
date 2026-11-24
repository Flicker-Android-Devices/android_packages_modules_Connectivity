/*
 * Copyright (C) 2026 The Android Open Source Project
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

import java.nio.ByteBuffer;

/**
 * DHCPv6 RELEASE packet class, a client sends a Release message to indicate that it will
 * no longer use one or more of the assigned addresses.
 *
 * https://tools.ietf.org/html/rfc8415#section-18.2.7
 */
public class Dhcp6ReleasePacket extends Dhcp6Packet {
    Dhcp6ReleasePacket(int transId, int elapsedTime, @NonNull final byte[] clientDuid,
            @NonNull final byte[] serverDuid, @NonNull final byte[] iana) {
        super(transId, elapsedTime, clientDuid, serverDuid, null /* iapd */, iana);
    }

    @Override
    public byte getMessageType() {
        return DHCP6_MESSAGE_TYPE_RELEASE;
    }

    @Override
    public ByteBuffer buildPacket() {
        final ByteBuffer packet = ByteBuffer.allocate(DHCP_MAX_LENGTH);
        final int msgTypeAndTransId = (DHCP6_MESSAGE_TYPE_RELEASE << 24) | mTransId;
        packet.putInt(msgTypeAndTransId);

        addTlv(packet, DHCP6_SERVER_IDENTIFIER, mServerDuid);
        addTlv(packet, DHCP6_CLIENT_IDENTIFIER, mClientDuid);
        addTlv(packet, DHCP6_ELAPSED_TIME, (short) (mElapsedTime & 0xFFFF));
        addTlv(packet, DHCP6_IA_NA, mIaNa);

        packet.flip();
        return packet;
    }
}
