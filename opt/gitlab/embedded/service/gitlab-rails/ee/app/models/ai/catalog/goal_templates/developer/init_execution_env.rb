# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        class InitExecutionEnv
          TEMPLATE = <<~GOAL.strip
            Initialize the Duo Agent Platform execution environment for repository
            `%{project_full_path}` (default branch: `%{default_branch}`).

            **Your task:** analyze the repository's tech stack, then create
            `.gitlab/duo/agent-config.yml` and open a merge request.

            ## Background

            `.gitlab/duo/agent-config.yml` configures the CI container every CI-launched
            Duo Agent Platform flow runs in. It is read only from the default branch.
            Schema reference:
            https://docs.gitlab.com/user/duo_agent_platform/flows/execution/#create-the-configuration-file

            Without this file, every flow falls back to a generic container that does
            not include the project's language toolchain or dependencies.

            ## Phase 1 — Analyze

            Retrieve the current user ID (for MR assignment), then inspect the repository:

            1. Identify the primary language and build tool from build files:
               `pom.xml`, `package.json`, `pyproject.toml`, `requirements.txt`, `Gemfile`,
               `go.mod`, `Cargo.toml`, `composer.json`, `build.gradle`, `build.sbt`.

            2. For each build file found, read it to extract:
               - Language version (for example, `<java.version>` in `pom.xml`,
                 `"engines.node"` in `package.json`, `requires-python` in `pyproject.toml`).
               - Dependency-manager invocation conventions (for example, `./mvnw` versus
                 `mvn`, `pnpm` versus `npm`, `poetry` versus `pip`).
               - Lockfile path (for cache keying): `pom.xml`, `package-lock.json`,
                 `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `Gemfile.lock`, `go.sum`,
                 `Cargo.lock`, `composer.lock`.

            3. Check `.gitlab-ci.yml` for the image the project's own CI uses today.
               Prefer aligning `image:` with what CI uses, so the agent runs in the same
               environment human developers and CI already trust.

            4. Note any validator tools declared in `.pre-commit-config.yaml`,
               `package.json#scripts`, `pyproject.toml [tool.*]`, or `Makefile` targets
               that the project expects to run before a commit lands. The agent must
               install these in `setup_script` because the Agent Platform does not yet
               read those files structurally.

            ## Phase 2 — Write `.gitlab/duo/agent-config.yml`

            Create a new branch from `%{default_branch}` and write
            `.gitlab/duo/agent-config.yml` with **only** these four top-level keys.
            Unknown keys are rejected by the schema:

            - `image` — official `<language>:<version>` image matching the detected
              stack (for example, `maven:3.9-eclipse-temurin-17`, `node:20-alpine`,
              `python:3.11-slim`, `ruby:3.3-slim`, `golang:1.22-alpine`). Avoid `latest`.
            - `setup_script` — array of shell commands that warm the cache and install
              any validator tools detected in Phase 1 step 4. Each command on its own
              line. Quiet flags preferred (for example, `-q`, `--silent`).
            - `cache` — `paths` is required; include the dependency-manager directory
              (for example, `.m2/repository/`, `node_modules/`, `.venv/`,
              `vendor/bundle/`). `key.files` should reference the project's lockfile.
            - `network_policy` — default to
              `include_recommended_allowed: true`. Add specific `allowed_domains` only
              when the analysis found evidence of an internal registry or service that
              the agent will need to reach.

            **Do not include** any key not listed above. Do not invent `services`,
            `before_script`, `variables`, `tags`, or any other GitLab CI–style key.

            Add a short comment header pointing to the documentation so future
            maintainers can find the schema.

            ## Phase 3 — Open a draft merge request

            Commit the file on the new branch and open a draft merge request targeting
            `%{default_branch}`, assigned to the current user. In the MR description,
            briefly explain:

            - The detected language and build tool, with the build file that informed it.
            - Why each `setup_script` line is needed (which validator or lockfile it
              addresses).
            - Anything the user should review before merging (image-tag choice, any
              `allowed_domains` added).
          GOAL

          def self.template
            TEMPLATE
          end

          def self.vars(resource:, **_)
            {
              project_full_path: resource.full_path,
              default_branch: resource.default_branch_or_main
            }
          end
        end
      end
    end
  end
end
