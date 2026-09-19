import unittest
from request_utils import RequestContext, get_protocol_anomaly_score

class TestProtocolAnomalyScore(unittest.TestCase):
    def test_no_fingerprint(self):
        context = RequestContext(headers={}, http_version="1.1")
        score = get_protocol_anomaly_score(context)
        self.assertEqual(score["protocolAnomalyScore"], 0.0)

    def test_spoofed_chrome_quic(self):
        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "x-quic-fp": "1;1=65536,4=50;i=0"
        }
        context = RequestContext(headers=headers, http_version="2.0")
        score = get_protocol_anomaly_score(context)
        self.assertEqual(score["protocolAnomalyScore"], 100.0)

    def test_legit_chrome_quic(self):
        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "x-quic-fp": "1;1=1572864,4=100;u=2,i"
        }
        context = RequestContext(headers=headers, http_version="2.0")
        score = get_protocol_anomaly_score(context)
        self.assertEqual(score["protocolAnomalyScore"], 0.0)

    def test_chrome_h2_header_anomaly(self):
        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "x-http2-fingerprint": "1|65535|0|invalid_order"
        }
        context = RequestContext(headers=headers, http_version="2.0")
        score = get_protocol_anomaly_score(context)
        self.assertEqual(score["protocolAnomalyScore"], 100.0)

if __name__ == "__main__":
    unittest.main()