from scripts.final_gate import run_rehearsal

def test_final_judge_rehearsal_gate():
    r = run_rehearsal(1)
    assert r['health_phase'] == 5
    assert r['stored'] == 10
    assert r['deny_filter_count'] == 5
    assert r['deny_vendor_count'] == 5
    assert r['raw_recovery'] == 'PASS'
    assert r['unknown_status'] == 'QUARANTINED'
    assert r['draft_auto_activated'] is False
    assert r['benchmark_visible'] is True
