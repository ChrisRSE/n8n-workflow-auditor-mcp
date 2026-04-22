"""FastMCP server entry point for the n8n Workflow Auditor."""

from fastmcp import FastMCP

from .tools import (
    analyse_instance,
    audit_workflow,
    check_webhooks,
    detect_deprecations,
    error_handling_coverage,
    generate_audit_report,
    scan_credentials,
    suggest_fixes,
)

mcp = FastMCP(
    "n8n Workflow Auditor",
    instructions=(
        "Audit n8n workflows for security issues, reliability anti-patterns, "
        "deprecated nodes, missing error handling, and credential hygiene. "
        "Start with audit_workflow for a full scan, or use the targeted tools "
        "(scan_credentials, check_webhooks, etc.) for focused checks."
    ),
)

mcp.tool()(audit_workflow)
mcp.tool()(scan_credentials)
mcp.tool()(check_webhooks)
mcp.tool()(detect_deprecations)
mcp.tool()(error_handling_coverage)
mcp.tool()(analyse_instance)
mcp.tool()(suggest_fixes)
mcp.tool()(generate_audit_report)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
