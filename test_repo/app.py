"""Sample application with deliberate security vulnerabilities for testing Sentinel."""

import os
import subprocess
import pickle


def insecure_eval(user_input):
    """Vulnerability: eval() on user input allows arbitrary code execution."""
    result = eval(user_input)
    return result


def insecure_exec(user_code):
    """Vulnerability: exec() on user input allows arbitrary code execution."""
    exec(user_code)


def insecure_os_system(command):
    """Vulnerability: os.system() runs shell commands and can lead to command injection."""
    os.system(command)


def insecure_subprocess():
    """Vulnerability: subprocess.call with shell=True allows command injection."""
    user_input = "ls -la"
    subprocess.call(user_input, shell=True)


def insecure_pickle(data):
    """Vulnerability: pickle.loads() can execute arbitrary code during deserialization."""
    return pickle.loads(data)


def insecure_yaml():
    """Vulnerability: yaml.load() without SafeLoader can execute arbitrary code."""
    import yaml
    data = "!!python/object/apply:os.system ['ls']"
    return yaml.load(data)


def sql_injection(user_id):
    """Vulnerability: SQL query built via string concatenation."""
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return query


def sql_injection_fstring(user_name):
    """Vulnerability: SQL query built via f-string."""
    conn = None
    query = f"SELECT * FROM users WHERE name = '{user_name}'"
    return query


def unsafe_tempfile():
    """Vulnerability: tempfile.mktemp() is vulnerable to race conditions."""
    import tempfile
    tmp_path = tempfile.mktemp()
    return tmp_path


def safe_function():
    """This function has no security issues."""
    name = "World"
    return f"Hello, {name}!"


def main():
    user_input = "__import__('os').system('echo vulnerable')"
    insecure_eval(user_input)


if __name__ == "__main__":
    main()
