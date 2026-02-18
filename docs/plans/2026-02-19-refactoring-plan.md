# OVH DNS Manager Refactoring Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform the current script into a robust, tested, and maintainable Python package.

**Architecture:** 
- Modular structure in `src/`.
- Standard configuration with `pyproject.toml`.
- Dependency management via `uv`.
- Linting and formatting with `ruff`.
- Automated testing with `pytest`.
- Improved security (dotenv, validation).
- API optimization (N+1 reduction).

**Tech Stack:** Python 3.10+, `ovh`, `rich`, `python-dotenv`, `pytest`, `ruff`, `uv`.

---

### Task 1: Environment & Tooling Setup

**Files:**
- Create: `pyproject.toml` (Done)
- Create: `.github/workflows/ci.yml`
- Modify: `.gitignore`

**Step 1: Finalize pyproject.toml**
Ensure all dependencies and tools (ruff, pytest) are configured.

**Step 2: Setup GitHub Actions CI**
Create `.github/workflows/ci.yml` to run ruff and pytest on push.

**Step 3: Update .gitignore**
Add `.venv`, `.ruff_cache`, `.pytest_cache`, and ensure `.env` is ignored.

**Step 4: Commit & Push**
```bash
git add pyproject.toml .github/workflows/ci.yml .gitignore src/
git commit -m "chore: setup project structure and CI"
git push origin oc
```

---

### Task 2: Refactor Credentials Management

**Files:**
- Modify: `src/credentials.py`

**Step 1: Integrate python-dotenv**
Replace manual `.env` parsing with `load_dotenv()` and `os.getenv()`.

**Step 2: Add Type Hints**
Add type annotations to all functions in `credentials.py`.

**Step 3: Robust Error Handling**
Improve exception catching and reporting during credential load/save.

**Step 4: Commit**
```bash
git add src/credentials.py
git commit -m "refactor(credentials): use python-dotenv and add type hints"
```

---

### Task 3: Security & Validation

**Files:**
- Create: `src/utils.py`
- Modify: `src/main.py`

**Step 1: Implement robust validation in `utils.py`**
- `validate_ip(ip: str) -> bool` using `ipaddress`.
- `validate_domain(domain: str) -> bool` using regex.

**Step 2: Update `main.py` to use validators**
Replace manual checks with calls to `utils.py`.

**Step 3: Commit**
```bash
git add src/utils.py src/main.py
git commit -m "feat(validation): add robust IP and domain validation"
```

---

### Task 4: API Optimization

**Files:**
- Modify: `src/main.py`

**Step 1: Optimize deletion**
Use `subDomain` filter in `client.get("/domain/zone/{domain}/record", subDomain=subdomain)` to fetch only relevant record IDs.

**Step 2: Optimize listing (where possible)**
Add optional filters to `list_dns_entries`.

**Step 3: Commit**
```bash
git add src/main.py
git commit -m "perf(api): optimize DNS record lookup during deletion"
```

---

### Task 5: Testing & Quality

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_utils.py`
- Create: `tests/test_credentials.py`

**Step 1: Setup pytest fixtures**
Mock the OVH client to avoid real API calls.

**Step 2: Implement Unit Tests**
Test validation logic and credential management.

**Step 3: Run full verification**
Run `ruff` and `pytest`.

**Step 4: Final Commit & PR**
```bash
git add tests/
git commit -m "test: add unit tests for validation and credentials"
gh pr create --title "Refactor and Robustify DNS Manager" --body "Complete overhaul of the tool for better security, performance, and maintainability."
```
