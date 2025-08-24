# Aegiscan Custom Rule Creation Guide
This document explains how to create and configure custom vulnerability detection rules for Aegiscan. By writing your own rules, you can tailor Aegiscan to the specific needs of your project and the libraries you use.

## 1. Introduction
Aegiscan is a rule-based SAST (Static Application Security Testing) tool for detecting vulnerabilities in Python code. Your rules are defined as YAML files, allowing you to specify particular code patterns, taint sources, sinks (vulnerable functions), and sanitizers (cleaners).

## 2. Rule File Structure (YAML)
Each rule should be defined as a separate YAML file in a rules directory, such as `aegiscan/rules`. A rule file must include the following key fields:
```yaml
id: AEGISCAN-CUSTOM-001
name: Custom SQL Injection Rule
severity: HIGH
cwe: CWE-89
description: User-controlled input used directly in an SQL query.
sources:
  - name: request.args.get
    type: CALL
  - name: request.form.get
    type: CALL
sinks:
  - name: sqlite3.cursor.execute
    type: CALL
  - name: psycopg2.cursor.execute
    type: CALL
sanitizers:
  - name: int
    type: CALL
  - name: str.format
    type: CALL
patterns:
  - pattern: "cursor.execute(...)"
    description: Execution of an SQL query.
message: User-controlled input flows into an SQL query. This may lead to SQL injection.
fix: Use parameterized queries or an ORM for SQL queries. Never concatenate input directly into an SQL query.
```

### Field Descriptions
*   `id` (Required): A unique identifier for the rule. Typically in the format `AEGISCAN-XXX-YYY`.
*   `name` (Required): A human-readable name for the rule.
*   `severity` (Required): The severity of the detected vulnerability. Possible values: `INFO`, `LOW`, `MEDIUM`, `HIGH`.
*   `cwe` (Recommended): The relevant Common Weakness Enumeration (CWE) ID. (Example: `CWE-89` for SQL Injection).
*   `description` (Required): A brief explanation of what the rule detects.
*   `sources` (Required): Defines entry points for untrusted (tainted) data.
    *   `name`: The fully qualified name (FQN) or pattern of the source (e.g., `request.args.get`, `input`).
    *   `type`: The type of the source. Possible values: `CALL` (function/method call), `VARIABLE` (variable).
*   `sinks` (Required): Defines sensitive functions or methods where tainted data should not reach.
    *   `name`: The FQN of the sink (e.g., `os.system`, `subprocess.Popen`).
    *   `type`: The type of the sink. Possible values: `CALL`.
*   `sanitizers` (Optional): Defines functions or methods that cleanse or neutralize tainted data. Data passing through these functions is no longer considered tainted.
    *   `name`: The FQN of the sanitizer (e.g., `shlex.quote`, `int`).
    *   `type`: The type of the sanitizer. Possible values: `CALL`.
*   `patterns` (Required): Defines specific code patterns that Aegiscan will look for in the Python AST.
    *   `pattern`: A simple text pattern that can be used to match AST nodes (currently primarily used for fully qualified call names, similar to sinks). More advanced AST pattern matching capabilities may be added in the future.
    *   `description`: A brief description of what the pattern represents.
*   `message` (Required): The message to display to the user when a vulnerability is found.
*   `fix` (Required): Suggested action to remediate the detected vulnerability.

## 3. Understanding Python AST
Aegiscan uses the Abstract Syntax Tree (AST) to parse and analyze Python code. Having a basic understanding of the Python AST is beneficial for writing effective rules.

*   `ast` Module: Python's `ast` module provides the AST representation of Python code. When writing rules, understanding how your code is represented by `ast.parse()` will help you identify the correct names and types for `sources`, `sinks`, and `patterns`.
*   Fully Qualified Names (FQNs): Aegiscan tracks functions, methods, and variables by their fully qualified names (e.g., `os.system`, `flask.request.args.get`, `my_module.my_function`). It is crucial to use these names correctly in your rule definitions.

### Example: Command Injection Rule (`command_injection.yaml`)
The command injection rule detects the flow of user-controlled input into a command execution sink like `os.system`.

```yaml
id: AEGISCAN-001
name: Command Injection
severity: HIGH
cwe: CWE-77
description: A vulnerability where user-supplied input is directly appended to a system command.
sources:
  - name: input
    type: CALL
  - name: request.args.get
    type: CALL
  - name: request.form.get
    type: CALL
  - name: sys.argv
    type: VARIABLE
sinks:
  - name: os.system
    type: CALL
  - name: subprocess.run
    type: CALL
  - name: subprocess.Popen
    type: CALL
  - name: commands.getoutput
    type: CALL
sanitizers:
  - name: shlex.quote
    type: CALL
message: User-controlled input flows into a command execution function. This may lead to command injection.
fix: Use parameterized execution functions or `shlex.quote` to properly escape user input, and avoid `shell=True`.
```

## 4. Testing Your Rule
After creating a new rule, it is essential to test it to ensure it works as expected.

1.  Save your rules: Save your new YAML rule file in Aegiscan's rules directory (by default, `./aegiscan/rules`) or any directory you specify with the `--rules` argument when running Aegiscan.
2.  Write test code: Create example Python code that includes scenarios your rule should or should not detect (both vulnerable and safe code).
3.  Run Aegiscan: Execute Aegiscan on your test code:
    ```bash
    python run.py scan <path_to_your_test_code> --rules <path_to_rules_directory>
    ```
4.  Review results: Check Aegiscan's output. Ensure your rule detects vulnerable code and ignores safe code.

## 5. Tips and Best Practices
*   Be specific: Try to be as specific as possible in your `sources`, `sinks`, and `patterns` fields. Overly general rules can lead to false positives.
*   Use FQNs: Always use fully qualified names for functions and methods.
*   Utilize sanitizers: Reduce false positives by defining known sanitizers that can break the vulnerability chain.
*   Iterate and test: Rule development is an iterative process. Thoroughly test your rules after writing them and make adjustments as needed.
*   Learn Python AST: Understanding how the Python AST works will significantly enhance your ability to write more complex and accurate rules. Refer to the official Python `ast` module documentation and online resources.