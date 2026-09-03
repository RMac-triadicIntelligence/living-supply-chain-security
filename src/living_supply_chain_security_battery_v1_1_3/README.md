# Living Supply-Chain Security Falsification Battery v1.1.3

**Release date:** 2026-09-03  
**Paper:** Living Supply-Chain Security for Persistent AI Organisms  
**Principle:** proposals require external signed authorization before commitment.

This release has 117 tests and ten mapped claim groups. It includes
recursive inventory-name protections and an artifact snapshot boundary that
hashes plain immutable bytes without supplied conversion or verification hooks.

From this battery directory:

~~~bash
python -m pip install -r requirements.txt
python run_all.py
~~~

Artifact content must be exact built-in bytes, and metadata must be non-empty
plain strings. The factory enforces the content-type rule; commit and policy
eligibility validate a captured immutable value. An artifact subclass's verify
method is not invoked by those enforcement paths.

Constructor authority pins, commit-time signed artifact binding, the policy
identifier LIVING-SCS-POLICY-V1.1, and Living-AI-BOM sequence semantics are retained.
The battery directory, package metadata, and receipt identify v1.1.3, released
on 2026-09-03.

See the package-root docs for verification commands, the claim boundary, and
current receipts. The submitted 111-test source is retained under root history.
