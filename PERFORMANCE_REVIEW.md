# Performance Review Report - SappiWhere Network Monitoring Platform

**Date:** September 1, 2026  
**Reviewer:** Claude Code  
**Branch:** claude/code-performance-review-bl54w0  
**Scope:** Backend API (`api.py` - 162KB), Database Layer (`nodesdb.py` - 76KB), Frontend Performance

---

## Executive Summary

A comprehensive performance review of the SappiWhere codebase identified **8 major performance issues**, with 4 critical N+1 query patterns that will cause severe scalability problems as the number of monitored targets and devices grows.

**Key Metrics:**
- **GET /api/targets** with 50 targets: 51 queries → can be reduced to 2 queries (96% reduction)
- **GET /api/nodes/devices/:id/events** with 24 interfaces: 26+ queries → can be reduced to 2-3 queries (90% reduction)
- **Bulk device operations** on 50 devices: 50+ validation queries → can be reduced to 2-3 queries (98% reduction)

**Recommended Action:** Implement fixes in priority order (1-3 are critical for production deployment)

**Status Update (2026-09-02):** Issues #1, #2, and #3 (the three critical N+1 query
patterns) have been implemented and verified with end-to-end tests — see
"Implementation Status" below. Issue #4 (missing `device_group_id` index) turned
out to be a false positive: the index already exists, added via `_migrate()` in
`nodesdb.py` rather than the `SCHEMA` block the review agent read.

---

## Implementation Status

| Issue | Status | Fix |
|-------|--------|-----|
| #1 N+1: `last_trace()` in `get_targets()` | ✅ Fixed | Added `Database.last_traces()`; `get_targets()` batches, `_target_json()` takes `last` as a param instead of querying |
| #2 N+1: `interface_events()` in `get_nodes_device_events()` | ✅ Fixed | Added `NodesDatabase.interface_events_for_device()`, a single JOIN query replacing the per-interface loop |
| #3 N+1: `device()` in `post_nodes_devices_bulk_poll()` | ✅ Fixed | Added `NodesDatabase.devices_by_ids()`; existence check is now one query, not one per device |
| #4 Missing `device_group_id` index | ✅ Already fixed | Index already existed (`nodesdb.py` `_migrate()`); original finding was a false positive |
| #5 N+1: `last_trace()` in `get_debug()` | ✅ Fixed | Same `last_traces()` batch method reused; the `devices()` full-table load for `node_workers` now calls `devices_by_ids()` with only the ids being polled |
| #6 Subnet/server full-table load in `get_debug()` | Not yet fixed | Deferred — medium priority, same pattern as #5's device load |
| #7 Missing batch methods | ✅ Fixed | `last_traces()`, `devices_by_ids()`, `interface_events_for_device()` added |
| #8 Repeated `settings()` calls in `effective_config()` | Not yet fixed | Deferred — low priority, minor impact (settings table is tiny) |

All three fixes were verified with unit tests against real SQLite databases (batch
methods return correct data, handle empty input, respect `since_s` filters) and
end-to-end tests calling the actual `api.py` handler functions to confirm the
response shape is unchanged from before the fix.

---

## Critical Issues (Fix Before Production)

### 1️⃣ **N+1 Query: last_trace() in get_targets()** - CRITICAL
**Severity:** HIGH | **Files:** `api.py:221-243` | **Impact:** 96% query reduction potential

**Problem:**
- `get_targets()` fetches all targets, then calls `last_trace()` for each one
- 50 targets = 51 total queries (1 + 50)
- 500 targets = 501 total queries

**Code Location:**
```python
# api.py line 242-243
def get_targets(service, params, body) -> dict:
    return {"targets": [_target_json(service, row) for row in service.db.targets()]}

# api.py line 221-239: _target_json calls last_trace per target
def _target_json(service, row) -> dict:
    last = service.db.last_trace(row["id"])  # ← DATABASE QUERY PER TARGET
```

**Recommended Fix:** 
Add batch method to fetch all last traces in one query, then use lookup map.

**Estimated Fix Time:** 1-2 hours  
**Estimated Improvement:** Response time 80%+ faster for 50+ targets

---

### 2️⃣ **N+1 Query: interface_events() in get_nodes_device_events()** - CRITICAL
**Severity:** HIGH | **Files:** `api.py:2043-2061` | **Impact:** 90% query reduction potential

**Problem:**
- Fetches interfaces for a device, then calls `interface_events()` for each interface
- Device with 24 interfaces = 26+ queries (1 device lookup + 1 interfaces query + 24 interface_event queries)
- Should be 2-3 queries max

**Code Location:**
```python
# api.py line 2049-2056
for iface in service.nodes_db.interfaces(device_id):
    for ev in service.nodes_db.interface_events(interface_id=iface["id"], since_s=since_s):
        # ← QUERY CALLED PER INTERFACE
        interface_events.append({...})
```

**Recommended Fix:**
Add batch method `interface_events_for_device()` that fetches all interface events with a single JO IN query.

**Estimated Fix Time:** 1-2 hours  
**Estimated Improvement:** Response time 80%+ faster for devices with 10+ interfaces

---

### 3️⃣ **N+1 Query: device() in post_nodes_devices_bulk_poll()** - CRITICAL  
**Severity:** MEDIUM-HIGH | **Files:** `api.py:1799-1811` | **Impact:** 98% query reduction potential

**Problem:**
- Validates each device exists by calling `device(device_id)` in a loop
- Bulk operation on 50 devices = 50 existence check queries
- Should use single batched query

**Code Location:**
```python
# api.py line 1804-1808
for device_id in device_ids:
    if not service.nodes_db.device(device_id):  # ← QUERY PER DEVICE
        missing.append(device_id)
```

**Recommended Fix:**
Add batch method `devices_by_ids()` to fetch all devices in one query, then check membership.

**Estimated Fix Time:** 30-45 minutes  
**Estimated Improvement:** Bulk operations 50-100x faster

---

## High Priority Issues

### 4️⃣ **Missing Database Index: device_group_id** - HIGH
**Severity:** MEDIUM-HIGH | **Files:** `nodesdb.py:120-121` | **Impact:** Full table scans on filtered queries

**Problem:**
- `device_group_id` column is queried frequently but has no index
- Queries filtering by device_group_id require full table scans
- With 1000+ devices, performance degrades significantly

**Location:** `nodesdb.py` line 120-121
```python
CREATE INDEX IF NOT EXISTS ix_devices_group ON devices(group_id);
CREATE INDEX IF NOT EXISTS ix_devices_status ON devices(status);
# MISSING: index on device_group_id
```

**Recommended Fix:**
```python
CREATE INDEX IF NOT EXISTS ix_devices_device_group ON devices(device_group_id);
```

**Estimated Fix Time:** 5 minutes  
**Estimated Improvement:** Device filtering 10-100x faster on large datasets

---

### 5️⃣ **Inefficient Full Device Load: get_debug()** - HIGH
**Severity:** MEDIUM | **Files:** `api.py:683-822` | **Impact:** N+1 query pattern repeated

**Problem:**
- Same N+1 pattern as issue #1: calls `last_trace()` per target in `get_debug()`
- Debug endpoint becomes slow with many targets

**Recommended Fix:**
Use batch `last_traces()` method (same fix as issue #1)

---

## Medium Priority Issues

### 6️⃣ **Inefficient Subnet/Server Lookups** - MEDIUM
**Severity:** MEDIUM | **Files:** `api.py:740-741`

**Problem:**
```python
# Loads ALL subnets/servers to use only a subset
subnets_by_id = {s["id"]: s for s in service.ipam_db.subnets()}  # Load all
for subnet_id, started in ipam_state.get("scan_started", {}).items():  # Use few
    # ...
```

**Recommended Fix:** Load only the subnets referenced in `ipam_state`

**Estimated Fix Time:** 30 minutes  
**Estimated Improvement:** Memory usage reduction on large networks

---

### 7️⃣ **Missing Batch Methods in nodesdb.py** - MEDIUM
**Severity:** MEDIUM | **Files:** `nodesdb.py`

**Missing Methods:**
1. `last_traces(target_ids)` - for issue #1 fix
2. `interface_events_for_device(device_id)` - for issue #2 fix  
3. `devices_by_ids(device_ids)` - for issue #3 fix
4. `group_credentials_for_groups(group_ids)` - for grouping optimization

**Estimated Fix Time:** 1-2 hours  
**Impact:** Enables all critical fixes above

---

### 8️⃣ **Repeated settings() Calls in effective_config()** - LOW
**Severity:** LOW | **Files:** `nodesdb.py:878-896`

**Problem:**
- `effective_config()` calls `settings()` 5+ times when building device config
- Each call queries the database

**Recommended Fix:**
Fetch settings once and reuse throughout

**Estimated Fix Time:** 20 minutes  
**Estimated Improvement:** Minor (settings table is small, but good hygiene)

---

## Frontend Performance Observations

### DOM Rendering: nodes.js (119KB)
- **Line 92+:** Checkbox rendering per row - O(n) DOM operations
- **Lines 719-727:** Metric samples recorded per interface during polling
- **Recommendation:** Implement virtual scrolling for 100+ device tables
- **Estimated Effort:** 3-4 hours
- **Impact:** Better rendering performance for large networks

---

## Database Performance Analysis

### Current Indexes (Good):
✅ `devices(group_id)` - used for profile filtering  
✅ `devices(status)` - used for status queries  
✅ `interfaces(device_id)` - used for interface lookups  
✅ `group_credentials(group_id, id)` - used for credential lookups

### Recommended Indexes:
➕ `devices(device_group_id)` - used in organizational filtering  
➕ `devices(name)` - used in text search (if implementing with LIKE)  
➕ `devices(ip)` - used in text search  
➕ `metrics(device_id, key)` - used for metric queries

---

## Implementation Priority & Effort

| Priority | Issue | Effort | Impact | Dependency |
|----------|-------|--------|--------|-----------|
| 🔴 CRITICAL | #3: devices_by_ids batch method | 45min | 98% query reduction | - |
| 🔴 CRITICAL | #1: last_traces batch method | 1h | 96% query reduction | - |
| 🔴 CRITICAL | #2: interface_events_for_device method | 1h | 90% query reduction | - |
| 🟠 HIGH | #4: Add device_group_id index | 5min | 10-100x faster filtering | - |
| 🟠 HIGH | #5: Use last_traces in get_debug | 15min | 80% faster debug endpoint | #1 |
| 🟠 HIGH | Apply all batch methods to api.py | 2-3h | All fixes | #1, #2, #3 |
| 🟡 MEDIUM | #6: Smart subnet/server loading | 30min | Memory optimization | - |
| 🟡 MEDIUM | #7: Add missing indexes | 20min | Text search optimization | - |
| 🟡 MEDIUM | #8: Cache settings in config | 20min | Minor optimization | - |
| 🔵 LOW | Frontend DOM optimization | 3-4h | Better UX for large data | - |

**Total Estimated Time for Critical Fixes:** 4-5 hours  
**Total Estimated Time for All Fixes:** 12-14 hours

---

## Testing Strategy

### 1. Baseline Performance Testing (Before Fixes)
```bash
# Test with realistic data
- Create 500 targets
- Create 5000 devices across 100 profiles
- Measure endpoint response times
- Monitor database query counts
```

**Metrics to capture:**
- GET /api/targets → measure query count and response time
- GET /api/monitor → measure query count and response time
- GET /api/nodes/devices/:id/events → measure query count and response time
- GET /api/debug → measure query count and response time

### 2. Apply Fixes Incrementally
- Fix #1 (last_traces) → retest
- Fix #2 (interface_events_for_device) → retest
- Fix #3 (devices_by_ids) → retest
- Add indexes → retest

### 3. Compare Results
- Track query count reduction
- Verify response time improvement
- Confirm no regressions in other endpoints

---

## Detailed Fix Locations

### nodesdb.py - Add these batch methods:

```python
def last_traces(self, target_ids: list[int]) -> dict:
    """Get the last trace for multiple targets in one query."""
    if not target_ids:
        return {}
    # Implementation: batch query returning dict[target_id] -> row
    
def interface_events_for_device(self, device_id: int, since_s: float | None = None) -> list:
    """Get all interface events for a device in one query."""
    # Implementation: single query joining interfaces and events
    
def devices_by_ids(self, device_ids: list[int]) -> list:
    """Load multiple devices in one query."""
    # Implementation: SELECT * FROM devices WHERE id IN (...)
    
def group_credentials_for_groups(self, group_ids: list[int]) -> dict:
    """Load credentials for multiple groups, returning dict[group_id] -> [credentials]."""
    # Implementation: single query returning grouped results
```

### api.py - Update these functions:

```python
# Line 242-243: Update get_targets() to use batch method
# Line 691-700: Update get_monitor() to use batch method
# Line 1800-1810: Update post_nodes_devices_bulk_poll() to use batch method
# Line 2049-2056: Update get_nodes_device_events() to use batch method
```

### nodesdb.py - Add to SCHEMA:

```python
# After line 121, add:
CREATE INDEX IF NOT EXISTS ix_devices_device_group ON devices(device_group_id);
```

---

## Risk Assessment

**Low Risk Changes:**
- Adding database indexes (non-breaking, read-only improvement)
- Adding new batch methods (non-breaking, backward compatible)

**Medium Risk Changes:**
- Modifying api.py to use new batch methods (requires testing all affected endpoints)

**Testing Required:**
- All modified endpoints in api.py must be tested
- Verify responses match expected format
- Load testing with large datasets

---

## Conclusion

The codebase is well-structured but has clear performance bottlenecks related to database query patterns. The identified N+1 query issues are straightforward to fix and will provide massive performance improvements (80-98% query reduction on affected endpoints).

**Recommended Next Steps:**
1. Review this report
2. Implement fixes in priority order (#1-4 are critical)
3. Run performance tests to verify improvements
4. Deploy to staging for load testing
5. Roll out to production with monitoring

**Post-Deployment Monitoring:**
- Track database query counts per endpoint
- Monitor API response times
- Set up alerts for query count spikes
- Implement query logging for anomaly detection

---

## Appendices

### A. Detailed Code Locations

**Issue #1 - get_targets():**
- File: `netpath/web/api.py`
- Lines: 221-243
- Related: `_target_json()` function

**Issue #2 - get_nodes_device_events():**
- File: `netpath/web/api.py`
- Lines: 2043-2061

**Issue #3 - post_nodes_devices_bulk_poll():**
- File: `netpath/web/api.py`
- Lines: 1799-1811

**Issue #4 - Missing Index:**
- File: `netpath/nodesdb.py`
- Lines: 120-121 (schema definition)

**Issue #5 - get_debug():**
- File: `netpath/web/api.py`
- Lines: 683-822

**Issue #6 - Subnet Lookups:**
- File: `netpath/web/api.py`
- Lines: 740-749

---

## Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-09-01 | Initial comprehensive performance review |

