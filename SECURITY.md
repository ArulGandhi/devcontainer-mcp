# Security

This server runs model-written code in a container, behind OAuth. Reports of auth bypass, token leaks, container escape through the connector, or request smuggling are welcome.

Report privately through GitHub: Security tab, "Report a vulnerability". Do not open a public issue for a vulnerability. Expect a first reply within a week.

Supported: the latest release.

Out of scope: what code inside the container can reach through the mounts and network you gave it. That is the operator's configuration, see the security model in the README.
