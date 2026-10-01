# Scan Tech Assistant

A Chainlit chat app that helps SecurityMetrics scan technicians validate
disputed Nessus findings from a terminal. A tech enters a plugin ID; the app
locates the plugin's NASL source in a local mirror, reads it, and returns a
plain-language explanation plus draft commands the tech can adapt and run by
hand. It never touches a customer environment and never runs anything
itself.

## Installation

This app is built and deployed using Docker. The image bundles a mirror of
the Nessus plugin archive and builds a plugin ID -> file path index at build
time, so no external plugin source is needed at runtime.

The image typically will be built and pushed via GitHub Actions workflows
automatically when associated files are changed. If you need to manually
build an image, run the following command from the root of the repository:

```bash
docker build -t scan_tech_assistant:latest apps/scan_tech_assistant
```

## Configuration

The following environment variables can be set to configure the app:

| Variable             | Description                                             | Default          |
| -------------------- | --------------------------------------------------------- | ----------------- |
| `ANTHROPIC_API_KEY`  | API key used to call the Claude API.                     | _(empty)_        |
| `MODEL`              | The Claude model to use for generating testing procedures. | `claude-sonnet-5-5` |

## Usage

### Build and run from this repo

From the repo root (where the `Dockerfile` is):

```bash
# 1. Build the image (first build downloads the plugin archive and indexes it;
#    later builds that only change app code reuse those layers)
docker build -t scan_tech_assistant:latest .

# 2. Load a fresh API key into this shell without echoing it or saving it to history
read -rs ANTHROPIC_API_KEY && export ANTHROPIC_API_KEY

# 3. Start the container. `-e ANTHROPIC_API_KEY` with no value passes the variable
#    through from your shell, so the key never appears in the command line or `docker ps`
docker run -d --name scan_tech_assistant -p 8000:8000 -e ANTHROPIC_API_KEY scan_tech_assistant:latest

# 4. Open http://localhost:8000 and enter a numeric Nessus plugin ID
```

Useful follow-ups:

```bash
docker logs -f scan_tech_assistant                 # watch startup and request errors
docker rm -f scan_tech_assistant                   # stop and remove before re-running
docker run ... -e MODEL=claude-sonnet-5 ...        # override the default model
```

To pick up code changes: `docker rm -f scan_tech_assistant`, rebuild (step 1),
and run again (step 3). The key stays loaded in the same shell session.

Once running, the app looks up the plugin's NASL source, summarizes the
finding, and walks through a testing procedure the tech can run by hand to
validate the finding.
