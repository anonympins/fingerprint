import hashlib
import struct
from typing import Any, Dict, Optional


class TLSClientHelloParser:
    """Binary TLS Client Hello decoder to natively extract JA3 and JA4 strings."""
    GREASE_VALUES = {
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
        35466, 39578, 43690, 47802, 51914, 55926, 60038, 64150
    }

    @staticmethod
    def read_var_int(data: bytes, offset: int) -> tuple:
        if offset >= len(data):
            return None, offset
        first = data[offset]
        prefix = first >> 6
        first_val = first & 0x3f
        if prefix == 0:
            return first_val, offset + 1
        elif prefix == 1:
            if offset + 2 > len(data):
                return None, offset
            val = (first_val << 8) | data[offset + 1]
            return val, offset + 2
        elif prefix == 2:
            if offset + 4 > len(data):
                return None, offset
            val = (first_val << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]
            return val, offset + 4
        else:
            if offset + 8 > len(data):
                return None, offset
            val = first_val
            for i in range(1, 8):
                val = (val << 8) | data[offset + i]
            return val, offset + 8

    @staticmethod
    def parse_quic_transport_parameters(data: bytes) -> Dict[int, Any]:
        params = {}
        offset = 0
        length = len(data)
        while offset < length:
            param_id, offset = TLSClientHelloParser.read_var_int(data, offset)
            if param_id is None:
                break
            param_len, offset = TLSClientHelloParser.read_var_int(data, offset)
            if param_len is None or offset + param_len > length:
                break
            param_val_bytes = data[offset:offset + param_len]
            offset += param_len
            if param_len > 0 and param_id in (1, 3, 4, 5, 6, 7, 8, 9, 11, 14):
                val, _ = TLSClientHelloParser.read_var_int(param_val_bytes, 0)
                params[param_id] = val if val is not None else param_val_bytes.hex()
            else:
                params[param_id] = param_val_bytes.hex()
        return params

    @staticmethod
    def parse_quic_control_frames(stream_data: bytes) -> Dict[str, Any]:
        frames = []
        frame_order = []
        settings = {}
        offset = 0
        length = len(stream_data)
        if length == 0:
            return {"frames": [], "frame_order": "", "settings": {}}

        if stream_data[0] == 0x00:
            offset = 1

        while offset < length:
            frame_type, offset = TLSClientHelloParser.read_var_int(stream_data, offset)
            if frame_type is None:
                break
            frame_len, offset = TLSClientHelloParser.read_var_int(stream_data, offset)
            if frame_len is None or offset + frame_len > length:
                break
            payload = stream_data[offset:offset + frame_len]
            offset += frame_len

            abbr = "s" if frame_type == 0x04 else (
                "m" if frame_type in (0x12, 0x02) else (
                    "p" if frame_type in (0x0f, 0xaf, 0xf0700) else (
                        "d" if frame_type in (0x10, 0x0d) else (
                            "g" if frame_type == 0x07 else "u"
                        )
                    )
                )
            )
            frames.append({"type": frame_type, "length": frame_len})
            frame_order.append(abbr)

            if frame_type == 0x04:
                s_offset = 0
                s_len = len(payload)
                while s_offset < s_len:
                    s_id, s_offset = TLSClientHelloParser.read_var_int(payload, s_offset)
                    if s_id is None:
                        break
                    s_val, s_offset = TLSClientHelloParser.read_var_int(payload, s_offset)
                    if s_val is None:
                        break
                    settings[s_id] = s_val

        return {
            "frames": frames,
            "frame_order": ",".join(frame_order),
            "settings": settings
        }

    @staticmethod
    def format_quic_fingerprint(params: Dict[int, Any], priority: str = "", frame_order: str = "") -> str:
        param_parts = [f"{k}={v}" for k, v in params.items()]
        fp = "1;" + ",".join(param_parts)
        if priority or frame_order:
            fp += f";{priority}"
        if frame_order:
            fp += f";{frame_order}"
        return fp

    @staticmethod
    def parse(binary: bytes) -> Optional[Dict[str, Any]]:
        length = len(binary)
        if length < 43:
            return None
        if binary[0] != 0x16 or binary[5] != 0x01:
            return None

        offset = 43
        if length < offset + 1:
            return None

        session_len = binary[offset]
        offset += 1 + session_len
        if length < offset + 2:
            return None

        ciphers_len = struct.unpack("!H", binary[offset:offset+2])[0]
        offset += 2
        if length < offset + ciphers_len + 1:
            return None

        ciphers = [struct.unpack("!H", binary[offset+i:offset+i+2])[0] for i in range(0, ciphers_len, 2)]
        offset += ciphers_len

        compression_len = binary[offset]
        offset += 1 + compression_len
        if length < offset + 2:
            return None

        extensions_len = struct.unpack("!H", binary[offset:offset+2])[0]
        offset += 2

        extensions, curves, points = [], [], []
        sig_algs, supported_versions = [], []
        has_sni = False
        alpn_protocol = ""
        quic_params = None
        ext_limit = offset + extensions_len
        while offset < ext_limit and offset + 4 <= length:
            ext_type = struct.unpack("!H", binary[offset:offset+2])[0]
            ext_len = struct.unpack("!H", binary[offset+2:offset+4])[0]
            offset += 4
            if offset + ext_len > length:
                break
            extensions.append(ext_type)
            if ext_type == 0:
                has_sni = True
            elif ext_type == 10 and ext_len >= 2:
                curves_len = struct.unpack("!H", binary[offset:offset+2])[0]
                curves.extend(struct.unpack(f"!{curves_len//2}H", binary[offset+2:offset+2+curves_len]))
            elif ext_type == 11 and ext_len >= 1:
                points_len = binary[offset]
                points.extend(binary[offset+1:offset+1+points_len])
            elif ext_type == 13 and ext_len >= 2:
                if offset + 2 <= length:
                    sig_algs_len = struct.unpack("!H", binary[offset:offset+2])[0]
                    for j in range(2, sig_algs_len + 2, 2):
                        if offset + j + 2 <= length and j + 2 <= ext_len:
                            sig_algs.append(struct.unpack("!H", binary[offset+j:offset+j+2])[0])
            elif ext_type == 16 and ext_len >= 3:
                if offset + 2 <= length:
                    alpn_list_len = struct.unpack("!H", binary[offset:offset+2])[0]
                    if ext_len >= 2 + alpn_list_len and offset + 2 + alpn_list_len <= length:
                        alpn_str_len = binary[offset + 2]
                        if alpn_list_len >= 1 + alpn_str_len:
                            alpn_protocol = binary[offset + 3:offset + 3 + alpn_str_len].decode("latin1", errors="ignore")
            elif ext_type == 43 and ext_len >= 1:
                if offset + 1 <= length:
                    versions_len = binary[offset]
                    for j in range(1, versions_len + 1, 2):
                        if offset + j + 2 <= length and j + 2 <= ext_len:
                            supported_versions.append(struct.unpack("!H", binary[offset+j:offset+j+2])[0])
            elif ext_type in (57, 0xffa5):
                if ext_len > 0 and offset + ext_len <= length:
                    quic_data = binary[offset:offset + ext_len]
                    quic_params = TLSClientHelloParser.parse_quic_transport_parameters(quic_data)
            offset += ext_len

        filter_grease = lambda arr: [v for v in arr if v not in TLSClientHelloParser.GREASE_VALUES]
        clean_ciphers = filter_grease(ciphers)
        clean_extensions = filter_grease(extensions)
        clean_curves = filter_grease(curves)
        clean_points = filter_grease(points)
        clean_sig_algs = filter_grease(sig_algs)
        clean_supported_versions = filter_grease(supported_versions)

        ssl_version = struct.unpack("!H", binary[9:11])[0]
        ja3_string = f"{ssl_version},{'-'.join(map(str, clean_ciphers))},{'-'.join(map(str, clean_extensions))},{'-'.join(map(str, clean_curves))},{'-'.join(map(str, clean_points))}"
        
        highest_version = ssl_version
        if clean_supported_versions:
            highest_version = max(clean_supported_versions)
        
        ja4_version = "12"
        if highest_version == 0x0304:
            ja4_version = "13"
        elif highest_version == 0x0303:
            ja4_version = "12"
        elif highest_version == 0x0302:
            ja4_version = "11"
        elif highest_version == 0x0301:
            ja4_version = "10"
            
        sni_status = "d" if has_sni else "i"
        num_ciphers = min(99, len(clean_ciphers))
        num_extensions = min(99, len(clean_extensions))
        
        ja4_alpn = "00"
        if alpn_protocol:
            ja4_alpn = (alpn_protocol + alpn_protocol) if len(alpn_protocol) == 1 else (alpn_protocol[0] + alpn_protocol[-1])
                
        ja4_a = f"t{ja4_version}{sni_status}{num_ciphers:02d}{num_extensions:02d}{ja4_alpn}"
        ciphers_str = ",".join(f"{c:04x}" for c in sorted(clean_ciphers))
        ja4_b = hashlib.sha256(ciphers_str.encode("utf-8")).hexdigest()[:12]
        
        extensions_str = ",".join(f"{e:04x}" for e in sorted(clean_extensions))
        sig_algs_str = ",".join(f"{s:04x}" for s in sorted(clean_sig_algs))
        ja4_c = hashlib.sha256(f"{extensions_str}_{sig_algs_str}".encode("utf-8")).hexdigest()[:12]

        result = {
            "ja3_string": ja3_string,
            "ja3_hash": hashlib.md5(ja3_string.encode("utf-8")).hexdigest(),
            "ja4_raw": f"{ja4_a}_{ja4_b}_{ja4_c}"
        }
        if quic_params is not None:
            result["quic_params"] = quic_params
            result["quic_fp"] = TLSClientHelloParser.format_quic_fingerprint(quic_params)
        return result