## Description

Summary of the changes introduced in this pull request.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New collector module
- [ ] Analysis / Topology improvement
- [ ] Renderer enhancement
- [ ] Documentation update

## Safety & Design Checklist

- [ ] **Zero System Modifications**: All operations are strictly observational.
- [ ] **Denylist Compliance**: No write, mutate, or restarting commands are executed.
- [ ] **Sanitization**: Any sensitive data (passwords, tokens, keys, hashes) is scrubbed.
- [ ] **Tests Added / Passing**: All unit and sanitization tests pass (`pytest tests/`).
- [ ] **No Outbound Network**: No remote telemetry or unprompted network calls.
