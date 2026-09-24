# Guide: Adding New Collectors

Linux Server Audit is modular. Adding a new collector requires implementing the `BaseCollector` interface and declaring a `CollectorManifest`.

## Step-by-Step Implementation

1. **Create Collector Module**:
   Create a new file in `src/serveraudit/collectors/<name>.py`.

2. **Define the Class**:
   ```python
   from typing import Any, Dict
   from ..core.collector import BaseCollector, CollectorManifest, CollectorResult, CollectorStatus
   from ..core.executor import CommandExecutor
   from . import register_collector

   @register_collector
   class ExampleCollector(BaseCollector):
       manifest = CollectorManifest(
           name="example",
           category="hardware",
           description="Inspects example hardware subsystem",
           requires_root=False,
           network_access=False,
           writes_system_state=False,
           collects_secrets=False,
           commands=["example-tool --json"],
           outputs=["example_data"],
       )

       def collect(self, executor: CommandExecutor, context: Dict[str, Any]) -> CollectorResult:
           # Check dependency
           if not executor.which("example-tool"):
               return CollectorResult(
                   collector=self.name,
                   status=CollectorStatus.DEPENDENCY_MISSING,
                   message="example-tool not found",
               )

           # Execute observational query
           res = executor.run(["example-tool", "--json"])
           if not res.success:
               return CollectorResult(
                   collector=self.name,
                   status=CollectorStatus.FAILED,
                   error=res.stderr,
               )

           # Return structured result
           return CollectorResult(
               collector=self.name,
               status=CollectorStatus.SUCCESS,
               data={"example_data": res.stdout},
           )
   ```

3. **Register in Registry**:
   Import your module in `src/serveraudit/collectors/__init__.py`.

4. **Add Unit Tests**:
   Add test cases with mock command fixtures in `tests/unit/`.
