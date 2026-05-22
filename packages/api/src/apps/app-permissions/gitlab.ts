import type { AppPermissionDefinition } from "./types";

export const gitlabPermissions: AppPermissionDefinition = {
  provider: "gitlab",
  groups: [
    {
      category: "read",
      tools: [
        {
          id: "git_clone",
          name: "Git clone / pull",
          description: "Clone or pull repository contents via git over HTTPS",
          hostPattern: "gitlab.com",
          pathPattern: "/*/*.git/git-upload-pack",
          method: "POST",
        },
        {
          id: "get_project",
          name: "Read project",
          description: "Get project details, files, and metadata",
          hostPattern: "gitlab.com",
          pathPattern: "/api/v4/projects/*",
          method: "GET",
        },
        {
          id: "list_projects",
          name: "List projects",
          description: "List visible projects for the authenticated user",
          hostPattern: "gitlab.com",
          pathPattern: "/api/v4/projects",
          method: "GET",
        },
        {
          id: "list_merge_requests",
          name: "List merge requests",
          description: "List merge requests in a project",
          hostPattern: "gitlab.com",
          pathPattern: "/api/v4/projects/*/merge_requests",
          method: "GET",
        },
        {
          id: "list_issues",
          name: "List issues",
          description: "List issues in a project",
          hostPattern: "gitlab.com",
          pathPattern: "/api/v4/projects/*/issues",
          method: "GET",
        },
      ],
    },
    {
      category: "write",
      tools: [
        {
          id: "git_push",
          name: "Git push",
          description: "Push commits to a repository via git over HTTPS",
          hostPattern: "gitlab.com",
          pathPattern: "/*/*.git/git-receive-pack",
          method: "POST",
        },
        {
          id: "create_merge_request",
          name: "Create merge request",
          description: "Create a new merge request",
          hostPattern: "gitlab.com",
          pathPattern: "/api/v4/projects/*/merge_requests",
          method: "POST",
        },
        {
          id: "create_issue",
          name: "Create issue",
          description: "Create a new issue in a project",
          hostPattern: "gitlab.com",
          pathPattern: "/api/v4/projects/*/issues",
          method: "POST",
        },
        {
          id: "create_note",
          name: "Create note",
          description: "Comment on an issue or merge request",
          hostPattern: "gitlab.com",
          pathPattern: "/api/v4/projects/*/*/*/notes",
          method: "POST",
        },
        {
          id: "trigger_pipeline",
          name: "Trigger pipeline",
          description: "Create a pipeline for a branch or tag",
          hostPattern: "gitlab.com",
          pathPattern: "/api/v4/projects/*/pipeline",
          method: "POST",
        },
      ],
    },
  ],
};
