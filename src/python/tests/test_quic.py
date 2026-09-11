import pytest
from engine import RequestContext, RequestUtils

def test_quic_anomaly_score_empty():
    context = RequestContext(
        client_ip="127.0.0.1", path="/", headers={}, query_params={}, cookies={}
    )
    score_data = RequestUtils.get_quic_anomaly_score(context)
    assert score_data["quicAnomalyScore"] == 0.0

def test_quic_anomaly_score_spoofed_chrome():
    context = RequestContext(
        client_ip="127.0.0.1", path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "x-quic-fp": "1;1=65536,4=50;i=0"
        },
        query_params={}, cookies={}
    )
    score_data = RequestUtils.get_quic_anomaly_score(context)
    assert score_data["quicAnomalyScore"] == 100.0

def test_quic_anomaly_score_legit_chrome():
    context = RequestContext(
        client_ip="127.0.0.1", path="/",
        headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "x-quic-fp": "1;1=1572864,4=100;u=2,i"
        },
        query_params={}, cookies={}
    )
    score_data = RequestUtils.get_quic_anomaly_score(context)
    assert score_data["quicAnomalyScore"] == 0.0