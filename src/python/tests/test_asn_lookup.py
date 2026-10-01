import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

import pytest
from asn_lookup import default_asn_lookup, AsnLookupEngine, HOSTING, CELLULAR, SATELLITE, RESIDENTIAL
from engine import calculate_analog_inconsistency_score


def test_datacenter_resolution_and_prior_score():
    engine = AsnLookupEngine()

    # Hetzner
    hetzner = engine.lookup("95.216.12.34")
    assert hetzner.type == "HOSTING"
    assert hetzner.base_score == 55.0
    assert hetzner.inflection_point == 0.85
    assert hetzner.tolerance_rotation is False

    # AWS
    aws = engine.lookup("54.210.1.20")
    assert aws.type == "HOSTING"
    assert aws.base_score == 55.0


def test_mobile_cgnat_resolution():
    engine = default_asn_lookup
    cgnat = engine.lookup("100.70.1.25")
    assert cgnat.type == "CELLULAR"
    assert cgnat.base_score == 10.0
    assert cgnat.inflection_point == 0.60
    assert cgnat.tolerance_rotation is True


def test_starlink_satellite_resolution():
    starlink = default_asn_lookup.lookup("98.97.10.5")
    assert starlink.type == "SATELLITE"
    assert starlink.base_score == 15.0
    assert starlink.jitter_tolerance == 150.0


def test_residential_default():
    res = default_asn_lookup.lookup("82.120.45.67")
    assert res.type == "RESIDENTIAL"
    assert res.base_score == 0.0
    assert res.inflection_point == 0.72


def test_analog_inconsistency_modulation():
    consistency = 0.80  # Incohérence légère de rendu
    score_datacenter = calculate_analog_inconsistency_score(consistency, HOSTING.inflection_point, 12.0)
    score_mobile = calculate_analog_inconsistency_score(consistency, CELLULAR.inflection_point, 12.0)

    assert score_datacenter > 55.0, "Sur Datacenter (0.80 < 0.85), la suspicion décolle au-dessus de 55.0"
    assert score_mobile < 10.0, "Sur Mobile (0.80 > 0.60), la variation est entièrement absorbée (< 10.0)"