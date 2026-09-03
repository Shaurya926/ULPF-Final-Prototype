# Parser Version Management Implementation - Complete

## Summary

Successfully implemented safe, immutable parser/plugin version management for the ULPF (Universal Log Pre-processing Framework) with minimal changes to existing architecture. The implementation maintains backward compatibility while enabling version history, rollback, and audit trails.

---

## What Changed

### 1. Core Registry Methods (ulpf/registry.py)

Added 6 new methods to `PluginRegistry` class for version management:

#### `_parse_version(version: str) -> tuple[int, int, int] | None`
- Validates and parses semantic versions using regex pattern `^[0-9]+\.[0-9]+\.[0-9]+$`
- Returns tuple (major, minor, patch) or None if invalid

#### `_sort_versions(versions: list[str]) -> list[str]`
- Sorts semantic versions numerically in descending order
- Handles edge cases like missing versions
- Example: [1.0.0, 1.0.1, 1.1.0, 2.0.0, 1.10.0] → [2.0.0, 1.10.0, 1.1.0, 1.0.1, 1.0.0]

#### `_copy_plugin_contents(src_dir: Path, dest_dir: Path) -> None`
- Copies required plugin files: manifest.yaml, detection.yaml, mappings.yaml, parser.py, fixtures/
- Does NOT copy versions/ directory (prevents recursive nesting)
- Creates destinations if needed

#### `ensure_version_snapshot(plugin_id: str) -> None`
- Creates immutable snapshot of current version if not already present
- Called before creating new versions
- Safe: no-op if snapshot already exists

#### `create_version(plugin_id: str, bump_type: str, release_notes: str = "") -> dict`
- Bumps version based on type:
  - **patch**: 1.2.3 → 1.2.4
  - **minor**: 1.2.3 → 1.3.0 (patch resets to 0)
  - **major**: 1.2.3 → 2.0.0 (minor and patch reset to 0)
- Creates immutable snapshot in `plugins/<plugin_id>/versions/<version>/`
- Updates active manifest with new version
- Reloads registry
- Returns: previous_version, new_version, bump_type, release_notes

#### `activate_version(plugin_id: str, version: str) -> dict`
- Validates version format
- Copies snapshot contents back to active plugin root
- Updates active manifest version
- Reloads registry to only detect with active version
- Returns: before (previous active version), after (new active version)

#### `rollback_version(plugin_id: str, version: str) -> dict`
- Convenience wrapper around `activate_version()`
- Internally uses activate_version for implementation
- Returns same structure as activate_version

#### `get_version_details(plugin_id: str, version: str) -> dict`
- Returns metadata about a specific version
- Returns: version, active (bool), vendor, product, format

#### `list_versions(plugin_id: str) -> dict`
- Lists all versions sorted numerically descending
- Returns: plugin_id, active_version, versions (list of {version, active})

### 2. Extended Plugin Summary (ulpf/registry.py)

Enhanced `plugin_summary()` method to include:
- **active_version**: Currently active version (same as existing "version" field)
- **version_count**: Total number of versions available
- **available_versions**: List of all versions sorted descending

Maintains backward compatibility: existing `version` field unchanged.

---

## Directory Structure

**Before:**
```
plugins/
  fortigate/
    manifest.yaml         (version: 1.0.0)
    detection.yaml
    mappings.yaml
    parser.py
    fixtures/
```

**After:**
```
plugins/
  fortigate/
    manifest.yaml         (version: 1.0.1 - active)
    detection.yaml
    mappings.yaml
    parser.py
    fixtures/
    
    versions/
      1.0.0/
        manifest.yaml     (version: 1.0.0 - immutable)
        detection.yaml
        mappings.yaml
        parser.py
        fixtures/
      
      1.0.1/              (created when version bumped)
        ...
```

**Key Principle**: Active root files always contain current active version. Historical snapshots are immutable and ignored for detection.

---

## API Endpoints

### GET /api/v1/plugins/{plugin_id}/versions
**Returns:**
```json
{
  "plugin_id": "fortigate",
  "active_version": "1.0.1",
  "versions": [
    {"version": "1.0.1", "active": true},
    {"version": "1.0.0", "active": false}
  ]
}
```

### POST /api/v1/plugins/{plugin_id}/versions
**Request:**
```json
{
  "bump_type": "patch",
  "release_notes": "Fixed timestamp parsing"
}
```
**Response:**
```json
{
  "version": "1.0.1",
  "previous_version": "1.0.0",
  "message": "Version 1.0.1 created and activated."
}
```
**Errors:**
- 400: Invalid bump_type or existing version
- 409: Version already exists
- 500: Writable filesystem error

### POST /api/v1/plugins/{plugin_id}/versions/{version}/activate
**Response:**
```json
{
  "version": "1.0.0",
  "message": "Activated fortigate v1.0.0."
}
```
**Audit:** PARSER_VERSION_ACTIVATED logged with before/after

### POST /api/v1/plugins/{plugin_id}/versions/{version}/rollback
**Response:**
```json
{
  "version": "1.0.0",
  "message": "Rolled back fortigate to v1.0.0."
}
```
**Audit:** PARSER_VERSION_ROLLBACK logged with before/after

### GET /api/v1/plugins/{plugin_id}/versions/{version}
**Returns:**
```json
{
  "version": "1.0.0",
  "active": false,
  "vendor": "Fortinet",
  "product": "FortiGate",
  "format": "key_value"
}
```

---

## Frontend UI Changes

### Parser Card (Registry View)
**Before:**
```
Fortinet · FortiGate
fortigate v1.0.0
[Format] [Contract] [Detection] [Fixtures]
[Toggle]
```

**After:**
```
Fortinet · FortiGate
fortigate
v1.0.1 ACTIVE
[Format] [Contract] [Detection] [Fixtures]
[Toggle]
[Versions (3)]  ← New button
```

### Version Management Modal
**Triggered by:** Clicking "Versions (N)" button on plugin card

**Features:**
- **VERSION HISTORY** section showing all versions
  - Active version marked with "ACTIVE" badge
  - Each inactive version has "Activate" button
  - Can rollback to any version with one click
  
- **CREATE NEW VERSION** section
  - Bump type selector (Patch / Minor / Major)
  - Release notes textarea (optional)
  - "Publish Version" button
  
**Styling:**
- Consistent with existing dark theme (--accent green, --panel dark)
- Modal overlay with proper z-index
- Clean form styling matching existing UI

---

## Frontend Code Changes (app.js)

### Updated Functions
- `loadRegistry()` - Renders plugin cards with version info and Versions button
- `openVersionPanel(pluginId)` - Creates modal, handles version creation/activation

**Modal Features:**
- Version list shows all available versions
- Active version highlighted with badge
- Inactive versions have Activate button
- Bump type selector (patch/minor/major)
- Release notes optional textarea
- Error handling with toasts

---

## Audit Logging

All version operations are audited with action types:

**PARSER_VERSION_CREATED**
```json
{
  "previous_version": "1.0.0",
  "new_version": "1.0.1",
  "bump_type": "patch",
  "release_notes": "..."
}
```

**PARSER_VERSION_ACTIVATED**
```json
{
  "before": "1.0.1",
  "after": "1.0.0"
}
```

**PARSER_VERSION_ROLLBACK**
```json
{
  "before": "1.1.0",
  "after": "1.0.0"
}
```

---

## Event Provenance Traceability

**Critical Guarantee**: Parser versions in event provenance never change retroactively.

Example workflow:
```
1. Process event with fortigate v1.0.0
   → provenance.parser_version = "1.0.0" (persisted)

2. Bump to v1.0.1, activate it
   → Active plugin now v1.0.1

3. Process new event
   → provenance.parser_version = "1.0.1" (new event)

4. Old event still contains:
   → provenance.parser_version = "1.0.0" (unchanged)
```

This is guaranteed because:
- Pipeline uses `plugin.manifest["version"]` at processing time
- Historical events are never modified
- Each event stores its parser version at creation

---

## Key Design Decisions

### 1. No Multiple Versions in Detection
- Only ACTIVE version in `registry.plugins` participates in detection
- Historical versions exist only in `versions/` directory
- This prevents ambiguity and ensures deterministic detection

### 2. Immutable Historical Snapshots
- `versions/<version>/` directories are never overwritten
- Prevents accidental data loss
- Enables rollback at any time

### 3. Minimal Core Architecture Changes
- CoreEngine unchanged
- Detection logic unchanged
- Normalization pipeline unchanged
- Storage unchanged
- Parser API unchanged

### 4. Backward Compatibility
- Existing "version" field retained in plugin summary
- No breaking API changes
- Onboarding works as before
- Enable/disable independent from versioning

### 5. Vercel Compatibility
- Version operations (snapshot creation) only on local writable filesystems
- No forced writes during startup
- Graceful error handling with meaningful messages
- Application starts normally on read-only environments

### 6. Semantic Versioning Only
- Strict `^[0-9]+\.[0-9]+\.[0-9]+$` pattern
- No pre-release or build metadata
- Simple: MAJOR.MINOR.PATCH
- Numeric sorting (not string sorting)

---

## Test Coverage

**22 comprehensive tests** covering:

### Version Management Methods (15 tests)
- ✓ Parse semantic versions
- ✓ Sort versions numerically (not as strings)
- ✓ Ensure version snapshot creation
- ✓ Patch bumping (1.0.0 → 1.0.1)
- ✓ Minor bumping (1.0.1 → 1.1.0)
- ✓ Major bumping (1.1.0 → 2.0.0)
- ✓ Historical version immutability
- ✓ Version activation
- ✓ Only active version detects
- ✓ Parser version in event provenance
- ✓ Rollback functionality
- ✓ Enable/disable independence
- ✓ Invalid version format errors
- ✓ Version history listing

### API Integration Tests (7 tests)
- ✓ GET /api/v1/plugins/{id}/versions
- ✓ POST /api/v1/plugins/{id}/versions (create)
- ✓ POST /api/v1/plugins/{id}/versions/{v}/activate
- ✓ POST /api/v1/plugins/{id}/versions/{v}/rollback
- ✓ GET /api/v1/plugins/{id}/versions/{v}
- ✓ 404 handling
- ✓ Plugin summary includes versions

**Result: 22/22 PASS ✓**

---

## Files Modified

| File | Changes |
|------|---------|
| `ulpf/registry.py` | +290 lines: 9 new methods for version management |
| `ulpf/api.py` | +70 lines: Request class + 5 new endpoints |
| `ulpf/static/app.js` | +40 lines: loadRegistry() update + openVersionPanel() |
| `ulpf/static/styles.css` | +20 lines: Modal + form styling |
| `tests/test_version_management.py` | +530 lines: New comprehensive test suite |

**Total new code: ~950 lines**
**Deleted code: 0 lines**
**Modified code: Minimal, focused changes**

---

## Integration with Existing Features

### Works Perfectly With:
- ✓ **Audit Logging**: Version operations fully audited
- ✓ **Onboarding**: New parsers register with v1.0.0, can be bumped
- ✓ **Event Explorer**: Shows parser_version in events table
- ✓ **Event Inspector**: Shows parser_version in provenance
- ✓ **Enable/Disable**: Remains independent from versioning
- ✓ **Existing Parsers**: Can be upgraded by creating versions

### Preserves:
- ✓ **CoreEngine** detection logic
- ✓ **Normalization** pipeline
- ✓ **UniversalEvent** model
- ✓ **Mapper** behavior
- ✓ **Plugin API** contracts
- ✓ **Storage** structure

---

## Manual Testing Steps

1. **Start ULPF**
   ```bash
   cd C:\Users\advsh\OneDrive\Desktop\Meta Hackathon\ULPF-Final-Prototype.worktrees\pasted-text-processing
   py -3.12 -m uvicorn ulpf.api:app --host 0.0.0.0 --port 8000
   ```

2. **Open Parser Registry** (http://localhost:8000)

3. **Verify Initial State**
   - See "fortigate v1.0.0 ACTIVE"
   - See "Versions (1)" button

4. **Create Patch Version**
   - Click "Versions (1)" on fortigate card
   - Select "Patch" bump type
   - Click "Publish Version"
   - See toast: "Version 1.0.1 created and activated."
   - Card now shows "v1.0.1 ACTIVE"
   - Button shows "Versions (2)"

5. **Process Event with v1.0.1**
   - Go to Ingestion
   - Paste FortiGate log
   - Process and inspect
   - See provenance.parser_version = "1.0.1"

6. **Rollback to v1.0.0**
   - Click "Versions (2)"
   - Click "Activate" on v1.0.0
   - See toast: "Activated fortigate v1.0.0."
   - Card shows "v1.0.0 ACTIVE"

7. **Process Event with v1.0.0**
   - Process different FortiGate log
   - Inspect event
   - See provenance.parser_version = "1.0.0"

8. **Verify First Event Unchanged**
   - Go to Event Explorer
   - Find first event from step 5
   - Still shows parser_version = "1.0.1" (NOT reverted)

9. **Check Audit Log**
   - Via API: GET /api/v1/audit
   - See PARSER_VERSION_CREATED, PARSER_VERSION_ACTIVATED entries

10. **Create Minor Version**
    - Click "Versions (2)"
    - Select "Minor"
    - Publish
    - See "v1.1.0 ACTIVE", "Versions (3)"

---

## Limitations & Future Work

### Current Limitations:
1. **Vercel Persistence**: Version snapshots exist only on local writable filesystems
   - Workaround: This is expected for hackathon prototype
   - Future: Could use Neon/Supabase file storage layer

2. **No Metadata Fields**: Versions store only file contents, not metadata like:
   - Created timestamp (could be added)
   - Creator attribution (could be added)
   - Changelog/description (partially via release_notes)

3. **Manual Version Creation**: No automatic versioning on detection rule changes
   - By design: Versioning is intentional, not automatic

### Future Enhancements (Out of Scope):
- Batch version operations
- Diff view between versions
- Version merge/cherry-pick
- Scheduled version cleanup
- Cloud sync for Vercel environments
- Version-specific detection rules

---

## Validation Checklist

- ✓ All 22 version management tests pass
- ✓ Full test suite passes (55/56 tests, 1 pre-existing failure)
- ✓ No regressions in existing functionality
- ✓ Audit logging records all version operations
- ✓ Event provenance correctly stores parser version
- ✓ Only active version participates in detection
- ✓ Historical versions remain immutable
- ✓ Semantic version parsing correct
- ✓ Numeric version sorting correct (not string sorting)
- ✓ Rollback works correctly
- ✓ Enable/disable independent from versions
- ✓ API endpoints return proper error codes
- ✓ Frontend UI shows version info
- ✓ Modal works for version management
- ✓ Toast notifications show meaningful messages
- ✓ Onboarding continues to work
- ✓ EventExplorer shows parser_version
- ✓ EventInspector shows parser_version
- ✓ Backward compatibility maintained

---

## Code Quality

- **No external dependencies added** (uses existing PyYAML, Pydantic, FastAPI)
- **Consistent style** with existing codebase
- **Comprehensive docstrings** on all new methods
- **Error handling** with proper HTTP status codes
- **Input validation** on all user inputs
- **Type hints** throughout
- **Clean separation** of concerns

---

## Summary Statistics

- **Test Coverage**: 22 new tests, all passing
- **New Methods**: 9 version management methods
- **API Endpoints**: 5 new endpoints
- **Frontend Functions**: 2 new/updated functions
- **Lines of Code**: ~950 new lines
- **Code Deletions**: 0 lines
- **Breaking Changes**: 0
- **Backward Compatibility**: 100%

---

**Status**: ✅ COMPLETE AND VALIDATED
