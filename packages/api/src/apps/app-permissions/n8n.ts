import type { AppPermissionDefinition } from "./types";

export const n8nPermissions: AppPermissionDefinition = {
  provider: "n8n",
  groups: [
    {
      category: "read",
      wildcard: {
        id: "read_all",
        name: "All read operations",
        description: "Read resources from the n8n public API",
        hostPattern: "*",
        pathPattern: "*",
        method: "GET",
      },
      tools: [
        {
          id: "list_workflows",
          name: "List workflows",
          description: "List workflows in the n8n instance",
          hostPattern: "*",
          pathPattern: "*/api/v1/workflows",
          method: "GET",
        },
        {
          id: "get_workflow",
          name: "Get workflow",
          description: "Get a workflow and its configuration",
          hostPattern: "*",
          pathPattern: "*/api/v1/workflows/*",
          method: "GET",
        },
        {
          id: "list_executions",
          name: "List executions",
          description: "List workflow executions",
          hostPattern: "*",
          pathPattern: "*/api/v1/executions",
          method: "GET",
        },
        {
          id: "get_execution",
          name: "Get execution",
          description: "Get details for a workflow execution",
          hostPattern: "*",
          pathPattern: "*/api/v1/executions/*",
          method: "GET",
        },
        {
          id: "editor_read",
          name: "Read editor resources",
          description: "Read resources through the authenticated editor API",
          hostPattern: "*",
          pathPattern: "*/rest/*",
          method: "GET",
        },
      ],
    },
    {
      category: "write",
      wildcard: {
        id: "write_all",
        name: "All write operations",
        description:
          "Create, update, run, and delete resources through the n8n public API",
        hostPattern: "*",
        pathPattern: "*",
        methods: ["POST", "PUT", "PATCH", "DELETE"],
      },
      tools: [
        {
          id: "create_workflow",
          name: "Create workflow",
          description: "Create a workflow",
          hostPattern: "*",
          pathPattern: "*/api/v1/workflows",
          method: "POST",
        },
        {
          id: "update_workflow",
          name: "Update workflow",
          description: "Update a workflow",
          hostPattern: "*",
          pathPattern: "*/api/v1/workflows/*",
          methods: ["PUT", "PATCH"],
        },
        {
          id: "activate_workflow",
          name: "Activate workflow",
          description: "Activate or deactivate a workflow",
          hostPattern: "*",
          pathPattern: "*/api/v1/workflows/*",
          method: "POST",
        },
        {
          id: "delete_workflow",
          name: "Delete workflow",
          description: "Delete a workflow",
          hostPattern: "*",
          pathPattern: "*/api/v1/workflows/*",
          method: "DELETE",
        },
        {
          id: "delete_execution",
          name: "Delete execution",
          description: "Delete execution history",
          hostPattern: "*",
          pathPattern: "*/api/v1/executions/*",
          method: "DELETE",
        },
        {
          id: "editor_write",
          name: "Modify editor resources",
          description:
            "Create, update, and delete resources through the authenticated editor API",
          hostPattern: "*",
          pathPattern: "*/rest/*",
          methods: ["POST", "PUT", "PATCH", "DELETE"],
        },
        {
          id: "mcp",
          name: "Use n8n MCP tools",
          description:
            "Call tools exposed by the instance-level n8n MCP server",
          hostPattern: "*",
          pathPattern: "*/mcp-server/*",
          methods: ["GET", "POST", "DELETE"],
        },
      ],
    },
  ],
};
