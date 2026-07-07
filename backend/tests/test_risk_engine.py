import pytest
from app.models.schemas import StaticAnalysisFlags
from app.engines.risk_engine import calculate_risk_score

def test_risk_score_zero_signal():
    """Test the zero-signal case (Safe). All flags are false/empty."""
    flags = StaticAnalysisFlags()
    
    base_score, ai_multiplier, final_score, band = calculate_risk_score(flags, ai_confidence=1.0)
    
    assert base_score == 0.0
    assert final_score == 0.0
    assert band == "Safe"

def test_risk_score_max_signal():
    """Test a hypothetical max-signal case (Critical). Should cap at 100."""
    flags = StaticAnalysisFlags(
        has_accessibility_abuse=True,
        has_sms_read_write=True,
        has_system_alert_window=True,
        dangerous_apis_found=["Runtime.exec", "addJavascriptInterface", "DexClassLoader", "PathClassLoader"],
        hardcoded_urls_ips=["http://malicious.com"] * 20, # Max out network risk
        targets_indian_banks=True
    )
    
    # AI confidence multiplier of 1.5 to push it to the absolute max
    base_score, ai_multiplier, final_score, band = calculate_risk_score(flags, ai_confidence=1.5)
    
    assert final_score == 100.0
    assert band == "Critical"

def test_risk_score_specific_combo():
    """
    Test the specific combination we'll cite in the demo:
    Accessibility + SMS + Overlay + targets Indian banks.
    """
    flags = StaticAnalysisFlags(
        has_accessibility_abuse=True,
        has_sms_read_write=True,
        has_system_alert_window=True,
        targets_indian_banks=True,
        dangerous_apis_found=[],
        hardcoded_urls_ips=[]
    )
    
    # Expected Base Score Calculation:
    # w1 = 25.0, w2 = 15.0, w3 = 10.0
    # PermRisk = 1.5 (Accessibility) + 1.0 (SMS) + 1.0 (Overlay) = 3.5
    # API_Risk = 0.0
    # Network_Risk = 1.0 (Indian banks target)
    # Base = (25.0 * 3.5) + 0 + (10.0 * 1.0) = 87.5 + 10 = 97.5
    
    base_score, ai_multiplier, final_score, band = calculate_risk_score(flags, ai_confidence=1.0)
    
    assert base_score == 97.5
    assert final_score == 97.5
    assert band == "Critical"
    
    # If the AI classification determines it's a known family, multiplier becomes 1.2
    base_score_2, ai_multiplier_2, final_score_2, band_2 = calculate_risk_score(flags, ai_confidence=1.2)
    assert ai_multiplier_2 == 1.2
    assert final_score_2 == 100.0 # Capped at 100
    assert band_2 == "Critical"

def test_risk_score_suspicious_band():
    """Test a case that falls into the Suspicious band (31-60)."""
    flags = StaticAnalysisFlags(
        has_sms_read_write=True, # PermRisk = 1.0
        dangerous_apis_found=["addJavascriptInterface"] # API_Risk = 0.5
    )
    
    # Base = (25.0 * 1.0) + (15.0 * 0.5) = 25.0 + 7.5 = 32.5
    base_score, ai_multiplier, final_score, band = calculate_risk_score(flags, ai_confidence=1.0)
    
    assert base_score == 32.5
    assert band == "Suspicious"
