# Agents use Handles; the Broker injects Secrets at execution time

An Agent must be able to use a Secret without its value ever entering the Agent's Context. We chose reference-and-inject: the Agent writes commands using opaque Handles, and a local Broker resolves them into the child process's environment (or a temp file) at the moment the command runs. A rewriting HTTP proxy was rejected as the foundation because it covers only HTTP; an execute-on-behalf MCP tool is offered as a thin wrapper over the same primitive, not as the primitive itself.
