## Summary

<!-- One or two sentences describing what this PR does and why. -->

## Checklist

- [ ] `pytest` passes locally (`pytest`)
- [ ] `ruff check .` exits 0
- [ ] `ruff format --check .` exits 0
- [ ] New rule has a YAML descriptor in `src/n8n_auditor/rules/definitions/`
- [ ] New rule has at least one "firing" and one "clean" fixture in `tests/fixtures/`
- [ ] New rule is registered in `src/n8n_auditor/engine.py` (`ALL_RULES`)
- [ ] `DECISIONS.md` updated if this PR makes an architectural choice
