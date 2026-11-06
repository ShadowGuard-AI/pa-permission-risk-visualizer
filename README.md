# pa-permission-risk-visualizer
Generates a visual representation of permission risks. The graph lists each risky file or directory as a node and draws an edge from the owner uid node that owns it, so an owner linked to a world-writable or setuid entry reads as a potential privilege escalation path. Can output graphs in formats like DOT or PNG. - Focused on Tools for analyzing and assessing file system permissions

The risk test reads the mode bits directly and flags setuid, setgid, group-writable, and world-writable files and directories. A run that scans nothing, or a run whose output file is not created (for example a PNG run without the graphviz dot binary), exits 1. The output file must not lie inside the scanned root.

## Install
`git clone https://github.com/ShadowGuard-AI/pa-permission-risk-visualizer`

## Requirements
Python 3 and the `rich` package (see requirements.txt). PNG output also needs the graphviz `dot` binary on PATH.

## Usage
`python3 main.py ROOT_PATH [-o output_file] [-f dot|png] [-v]`

## Parameters
- `-h`: Show help message and exit
- `ROOT_PATH`: (required) The root directory to analyze.
- `-o`, `--output-file`: The file to save the visualization to (default: `permission_risk_graph.png`).
- `-f`, `--output-format`: The format of the output file (default: `png`, options: `dot`, `png`).
- `-v`, `--verbose`: Enable verbose logging (debug level).

## License
MIT License. See LICENSE.
