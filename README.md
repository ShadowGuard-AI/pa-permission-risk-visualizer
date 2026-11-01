# pa-permission-risk-visualizer
Generates a visual representation of permission risks. The graph lists each risky file or directory as a node and draws an edge from the owner uid node that owns it, so an owner linked to a world-writable or setuid entry reads as a potential privilege escalation path. Can output graphs in formats like DOT or PNG. - Focused on Tools for analyzing and assessing file system permissions

The risk test reads the mode bits directly and flags setuid, setgid, group-writable, and world-writable files and directories. A run that scans nothing, or a run whose output file is not created (for example a PNG run without the graphviz dot binary), exits 1. The output file must not lie inside the scanned root.

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-risk-visualizer`

## Usage
`./pa-permission-risk-visualizer [params]`

## Parameters
- `-h`: Show help message and exit
- `-o`: No description provided
- `-f`: No description provided
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ
