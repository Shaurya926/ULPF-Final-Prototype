#!/usr/bin/env python3
from __future__ import annotations
import json, tempfile, sys
from datetime import datetime, timezone
from pathlib import Path
from fastapi.testclient import TestClient
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from ulpf.api import create_app  # noqa: E402

def run_rehearsal(index:int)->dict[str,object]:
    with tempfile.TemporaryDirectory(prefix=f"ulpf-final-{index}-") as d:
        client=TestClient(create_app(str(Path(d)/'gate.db'), str(ROOT/'plugins')))
        health=client.get('/health').json(); assert health['phase']==5 and health['offline_core'] is True and health['ai_required'] is False
        ds=client.get('/api/v1/demo/datasets/mixed').json(); assert ds['synthetic'] is True and len(ds['events'])==10
        processed=client.post('/api/v1/ingest/batch', json={'payloads':ds['events']}).json(); assert len(processed)==10 and all(i['status']=='STORED' for i in processed)
        events=client.get('/api/v1/events', params={'limit':100}).json(); denials=client.get('/api/v1/events', params={'action':'DENY','limit':100}).json()
        assert len(events)==10 and len(denials)==5 and len({e['observer']['vendor'] for e in denials})==5
        fg=next(e for e in events if e['observer']['vendor']=='Fortinet' and e['event']['action']=='ALLOW')
        ca=next(e for e in events if e['observer']['vendor']=='Cisco' and e['event']['action']=='ALLOW')
        assert fg['event']['action']==ca['event']['action']=='ALLOW'
        insp=client.get(f"/api/v1/events/{fg['event_id']}/inspect").json(); raw=client.get(f"/api/v1/events/{fg['event_id']}/raw").json()
        assert insp['raw']['payload']==raw['payload']==fg['raw']['payload']; assert insp['validation']['status']=='PASS'; assert len(insp['field_trace'])>=5
        ndjson=client.get('/api/v1/export/ndjson').text.strip().splitlines(); assert len(ndjson)==10 and all(json.loads(line).get('event_id') for line in ndjson)
        unknown_payload=(ROOT/'datasets/unknown/unknown_1.log').read_text(encoding='utf-8').strip()
        unknown=client.post('/api/v1/ingest/paste', json={'payload':unknown_payload}).json(); assert unknown['status']=='QUARANTINED' and unknown['reason']=='UNKNOWN_SOURCE' and len(unknown.get('detection_report') or [])==5
        analysis=client.post('/api/v1/onboarding/analyze', json={'payload':unknown_payload}).json(); assert analysis['field_count']>=3
        body={'payload':unknown_payload,'mappings':{'_detected_timestamp':'@timestamp','src':'source.ip','dst':'destination.ip','decision':'event.action'},'vendor':'MysteryVendor','product':'Edge Appliance','plugin_id':'mystery_appliance'}
        preview=client.post('/api/v1/onboarding/preview', json=body).json(); draft=client.post('/api/v1/onboarding/drafts', json=body).json()
        assert preview['validation']['ready_for_plugin_review'] in (True, False); assert draft['auto_activated'] is False and draft['status']=='DRAFT_REVIEW_REQUIRED'
        overview=client.get('/api/v1/overview').json(); assert overview['active_plugins']==5 and overview['published_benchmark'] is not None
        return {'rehearsal':index,'health_phase':health['phase'],'synthetic_events':len(ds['events']),'stored':len(events),'deny_filter_count':len(denials),'deny_vendor_count':len({e['observer']['vendor'] for e in denials}),'raw_recovery':'PASS','inspector_validation':insp['validation']['status'],'field_trace_entries':len(insp['field_trace']),'unknown_status':unknown['status'],'unknown_reason':unknown['reason'],'detection_attempts':len(unknown.get('detection_report') or []),'draft_status':draft['status'],'draft_auto_activated':draft['auto_activated'],'ndjson_lines':len(ndjson),'benchmark_visible':overview['published_benchmark'] is not None}

def main()->None:
    rehearsals=[run_rehearsal(i) for i in range(1,4)]
    airgap=json.loads((ROOT/'reports/phase4_airgap_check.json').read_text(encoding='utf-8'))
    benchmark=json.loads((ROOT/'reports/phase4_benchmark.json').read_text(encoding='utf-8'))
    assert airgap['network_required'] is False and benchmark['failures']==0
    report={'name':'ULPF final hackathon gate','generated_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),'status':'PASS','three_consecutive_rehearsals':'PASS','rehearsals':rehearsals,'airgap_process_check':airgap,'benchmark_snapshot':{'events':benchmark['events'],'events_per_sec':benchmark['events_per_sec'],'p50_ms':benchmark['latency_ms']['p50'],'p95_ms':benchmark['latency_ms']['p95'],'failure_rate':benchmark['failure_rate'],'claim_scope':benchmark['methodology']['claim_scope']},'claim_guardrails':['Synthetic/sanitized telemetry is labelled.','Benchmark is a reproducible local prototype baseline, not production scale.','Known-source parsing remains deterministic and offline.','Authoring assistance never auto-activates mappings.']}
    (ROOT/'reports/final_gate_report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    (ROOT/'reports/final_gate_report.md').write_text('# ULPF Final Hackathon Gate\n\n**Status:** PASS\n\n## Three consecutive demo rehearsals\n\n'+'\n'.join(f"- Rehearsal {r['rehearsal']}: {r['stored']} stored, {r['deny_filter_count']} DENY across {r['deny_vendor_count']} vendors, raw recovery {r['raw_recovery']}, unknown {r['unknown_status']}." for r in rehearsals)+f"\n\n## Benchmark snapshot\n\n- Events: **{benchmark['events']}**\n- Throughput: **{benchmark['events_per_sec']:.2f} events/sec**\n- p50: **{benchmark['latency_ms']['p50']:.2f} ms**\n- p95: **{benchmark['latency_ms']['p95']:.2f} ms**\n- Failure rate: **{benchmark['failure_rate']:.2%}**\n\n> Local single-process SQLite prototype baseline, not production throughput.\n\n## Air-gap proof\n\n- Network required: **{airgap['network_required']}**\n- Restart persistence: **{airgap['restart_persistence']}**\n", encoding='utf-8')
    print(json.dumps(report, indent=2, sort_keys=True))
if __name__=='__main__': main()
