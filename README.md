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

| Variable            | Description                                                | Default           |
| ------------------- | ---------------------------------------------------------- | ----------------- |
| `ANTHROPIC_API_KEY` | API key used to call the Claude API.                       | _(empty)_         |
| `MODEL`             | The Claude model to use for generating testing procedures. | `claude-sonnet-5` |

## Usage

Run the container with your API key set:

```bash
docker run -d -p 8000:8000 -e ANTHROPIC_API_KEY="your-api-key" scan_tech_assistant:latest
```

Once running, open the app in a browser and enter a numeric Nessus plugin
ID. The app will look up the plugin's NASL source, summarize the finding,
and walk through a testing procedure the tech can run by hand to validate
the finding.
