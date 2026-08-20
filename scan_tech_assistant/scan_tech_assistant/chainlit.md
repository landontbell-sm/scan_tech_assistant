# Scan Tech Assistant

Look up a Nessus plugin and get a plain-language explanation of why it fired —
built for the moment you're on a call with a customer and need an answer fast.

**How to use it:** type a plugin ID (the number off the report page) and send it.
The assistant will:

1. Locate the plugin's source
2. Pull out its CVEs, severity, and false-positive signals
3. Read the trigger logic and explain what it checks, what 
   response makes it fire, and why it might have failed
4. Generate test commands the agent can manually edit/run to validate the claims.
