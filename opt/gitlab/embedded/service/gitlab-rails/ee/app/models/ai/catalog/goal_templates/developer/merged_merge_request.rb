# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class Developer
        class MergedMergeRequest
          TEMPLATE = <<~GOAL.strip
            The merge request %{resource_url} has just been merged. It was implemented
            with Duo Developer sessions with the following session IDs: %{session_ids}
            Whenever you mention a session, link it as
            `%{project_url}/-/automate/agent-sessions/<SESSION_ID>`.

            Distill facts from these sessions' traces into repo harness improvements so
            future agent sessions avoid rediscovering the same things.

            ## 1. Get the traces

            For each session ID:

            ```sh
            glab api "ai/duo_workflows/workflows/<SESSION_ID>/trace.jsonl" > "/tmp/trace-<SESSION_ID>.jsonl"
            ```

            ## 2. Extract evidence

            Traces are JSONL event streams: agent reasoning, tool calls, tool results.
            Analyze them with `run_command` (`grep`, `python3`; `jq` may not be
            installed — use `python3 -c 'import json,sys;…'` as a portable
            alternative) instead of `read_file` to keep token use low.

            Collect findings backed by what actually happened in a trace (cite session
            plus events) — no speculation. Route each finding by root cause:

            1. **Missing binary or dependency** in the agent environment → add it to the
               `setup_script:` list in `.gitlab/duo/agent-config.yml`, creating the file
               if absent. File tools reject this path; read and edit it with `run_command`.
            2. **Misconfigured repo dev setup** (for example a broken hook or script) →
               fix that configuration directly; do not document workarounds instead.
            3. **Convention the agent had to discover by trial and error** (lint, test,
               build commands), or the repo's agent instructions misled it → update those
               instructions.

            For case 3, first determine the repo's convention from the root of the repo,
            then edit accordingly:

            - only `AGENTS.md` → edit it
            - only `CLAUDE.md` → edit it
            - both → if one is a symlink to the other, edit the real file; if independent,
              apply the same change to both
            - neither → create `AGENTS.md`

            These files are loaded into every session of many different agents, so:

            - Add only guidance that holds for common agents (never one agent's tool quirk)
              and for the whole class of mistake (for example how to check out a branch
              whether or not it exists on the remote), not a single incident.
            - Recommend the proper way; add a fallback only where the proper way is
              impractical for an autonomous agent.
            - Keep additions as short as clarity allows — every line costs tokens in every
              future session.

            Drop findings that occurred once with no sign they are systemic, and
            findings owned by files outside this repo (for example a skill hosted
            elsewhere) — mention those in the merge request description as observations
            instead of fixing them here.

            ## 3. Deliver

            If findings remain, apply them and open one merge request:

            - Keep the diff to the routed fixes above; unrelated code fixes and
              refactors are out of scope.
            - Branch off the default branch with a name matching
              `duo/distill/<short-description>`.
            - Commit following the repo's commit conventions (Conventional
              Commits if none are documented).
            - Write the title and description following the project's conventions, using
              a template from `.gitlab/merge_request_templates/` when one exists. For
              each change, state the root cause and why the change is needed with its
              session evidence, concisely enough that a reviewer can merge with
              confidence.
            - Begin the description with an origin section that explains why and how
              the merge request was created, so its author and reviewers are not
              surprised by it:
              ```
              ## Why this merge request exists

              This merge request was created automatically by the memory
              distillation trigger after %{resource_url} was merged. It distills improvements
              from these sessions: <link each analyzed session ID, for example
              [12345](%{project_url}/-/automate/agent-sessions/12345)>.

              It is assigned to `@%{author_username}`, the author of the merged merge
              request. %{reviewer_origin} Review it as you would any merge request. If
              the diff does not make sense, comment with the reason and close it.

              Feedback or issues with memory distillation? Comment on
              https://gitlab.com/gitlab-org/gitlab/-/work_items/613978
              ```
            - Do not create the merge request as a draft.
            - Assign the merge request to `%{author_username}` using `--assignee %{author_username}`.
            %{request_reviewer}

            ## 4. Report back

            Post a comment on the merged merge request %{resource_url} that begins
            with a short origin line so the author immediately understands the
            context, then summarizes the outcome:

            ```
            **Memory Distillation — Session Summary**

            Memory distillation ran automatically after this merge request was
            merged, started by the trigger configured in this project. It
            analyzed session(s) <link each analyzed session ID, for example
            [12345](%{project_url}/-/automate/agent-sessions/12345)> and opened
            <distilled MR link> (or: found no actionable improvements).

            Key findings:
            - <one-line summary per finding, citing the session>

            Feedback or issues with memory distillation? Comment on
            https://gitlab.com/gitlab-org/gitlab/-/work_items/613978
            ```
          GOAL

          def self.template
            TEMPLATE
          end

          def self.vars(resource:, params: {}, **_)
            author_username = resource.author&.username
            reviewer_username = resolve_reviewer_username(resource, author_username)

            {
              resource_url: Gitlab::UrlBuilder.build(resource),
              project_url: Gitlab::UrlBuilder.build(resource.project),
              session_ids: Array(params[:session_ids]).join(', '),
              author_username: author_username,
              reviewer_origin: reviewer_origin(reviewer_username),
              request_reviewer: request_reviewer(author_username, reviewer_username)
            }
          end

          # Picks a reviewer for the distilled MR who differs from the author:
          # 1. The user who merged the MR (when different from the author).
          # 2. Any reviewer on the merged MR (excluding the author).
          # 3. nil when no suitable reviewer exists.
          def self.resolve_reviewer_username(merge_request, author_username)
            merged_by = merge_request.metrics&.merged_by
            return merged_by.username if merged_by && merged_by.username != author_username

            merge_request.reviewers.find { |r| r.username != author_username }&.username
          end

          def self.reviewer_origin(reviewer_username)
            if reviewer_username.present?
              "The requested reviewer `@#{reviewer_username}` merged or reviewed the original merge request."
            else
              'No suitable reviewer could be identified — please request one manually.'
            end
          end

          def self.request_reviewer(_author_username, reviewer_username)
            if reviewer_username.present?
              "Request review from `#{reviewer_username}` using `--reviewer #{reviewer_username}`."
            else
              'Do not request review from anyone: no suitable reviewer could be determined ' \
                'who differs from the assignee, and the assignee cannot approve their own merge request.'
            end
          end
        end
      end
    end
  end
end
