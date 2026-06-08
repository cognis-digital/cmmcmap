"""CMMCMAP MCP server — exposes scan as an MCP tool for Cognis.Studio."""
from cognis_core.mcp import build_mcp_server
from cmmcmap.core import scan, TOOL_NAME

run_mcp_server = build_mcp_server(
    tool_name=TOOL_NAME,
    description="CMMC Level 2 practice mapper — stack-aware SSP skeleton generator",
    scan_fn=scan,
)

if __name__ == "__main__":
    run_mcp_server()
