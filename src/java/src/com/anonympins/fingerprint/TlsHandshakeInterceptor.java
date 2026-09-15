package com.anonympins.fingerprint;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.AttributeKey;
import java.util.Map;

/**
 * Intercettatore Netty per decodificare il ClientHello e calcolare JA3/JA4 prima dell'SSL Handshake.
 */
public class TlsHandshakeInterceptor extends ChannelInboundHandlerAdapter {
    public static final AttributeKey<String> JA3_HASH_KEY = AttributeKey.valueOf("ja3Hash");
    public static final AttributeKey<String> JA4_HASH_KEY = AttributeKey.valueOf("ja4Hash");
    public static final AttributeKey<String> JA3_RAW_KEY = AttributeKey.valueOf("ja3Raw");

    private ByteBuf handshakeBuffer;

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        handshakeBuffer = ctx.alloc().buffer();
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) {
        if (handshakeBuffer != null) {
            handshakeBuffer.release();
            handshakeBuffer = null;
        }
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof ByteBuf) {
            ByteBuf buf = (ByteBuf) msg;
            if (handshakeBuffer != null && handshakeBuffer.readableBytes() < 2048) {
                handshakeBuffer.writeBytes(buf.duplicate());
                
                if (handshakeBuffer.readableBytes() >= 5) {
                    int recordType = handshakeBuffer.getByte(0) & 0xFF;
                    // Verifica se il pacchetto è un Handshake Record (22 / 0x16)
                    if (recordType == 0x16) {
                        int recordLength = handshakeBuffer.getUnsignedShort(3);
                        if (handshakeBuffer.readableBytes() >= 5 + recordLength) {
                            byte[] recordBytes = new byte[5 + recordLength];
                            handshakeBuffer.readBytes(recordBytes);

                            Map<String, String> fp = TLSClientHelloParser.parse(recordBytes);
                            if (fp != null) {
                                ctx.channel().attr(JA3_HASH_KEY).set(fp.get("ja3_hash"));
                                ctx.channel().attr(JA4_HASH_KEY).set(fp.get("ja4_raw"));
                                ctx.channel().attr(JA3_RAW_KEY).set(fp.get("ja3_string"));
                            }
                            ctx.pipeline().remove(this); // Intercettamento completato, rimuove sé stesso
                        }
                    } else {
                        ctx.pipeline().remove(this); // Record non handshake, rimuove sé stesso
                    }
                }
            }
        }
        super.channelRead(ctx, msg);
    }
}