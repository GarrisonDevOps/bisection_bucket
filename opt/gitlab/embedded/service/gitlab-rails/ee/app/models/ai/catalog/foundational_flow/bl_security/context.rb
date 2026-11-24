# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module BlSecurity
        # Fields of agent_platform_bl_security_context
        # (schema: json_schemas/agent_platform/agent_platform_bl_security_context): the business
        # logic security scan's runtime dials, sourced from project CI/CD variables.
        #
        # Built at workflow start, so every start path (API, Duo Chat, restart and resume)
        # carries the dials.
        class Context
          # Project CI/CD variable -> context key.
          SCAN_DIAL_VARIABLES = {
            'BL_SCAN_EFFORT' => 'scan_effort',
            'BL_TARGET_FILES' => 'target_files'
          }.freeze

          # scan_effort when BL_SCAN_EFFORT is unset, blank or not a known tier.
          DEFAULT_SCAN_EFFORT = 'low'

          # The engine's scan_effort tiers.
          SCAN_EFFORTS = %w[low standard high].freeze

          def self.call(runtime_context:)
            new(
              project: runtime_context.project,
              primary_branch: runtime_context.primary_branch,
              goal: runtime_context.goal
            ).call
          end

          def initialize(project:, primary_branch:, goal:)
            @project = project
            @primary_branch = primary_branch
            @goal = goal
          end

          # Unset fields are left out, not null, because the schema types them as strings.
          # Only `*`-scoped variables are read: a workflow has no environment when it starts,
          # and protected variables are meant for protected refs only.
          def call
            return unless project
            return unless ::Ai::Catalog::FoundationalFlow.bl_security_experimental.enabled_for?(project.root_ancestor)

            variables = project.variables.unprotected.env_var.by_environment_scope('*')
              .by_key(SCAN_DIAL_VARIABLES.keys)
            dials = variables.to_h { |variable| [SCAN_DIAL_VARIABLES[variable.key], variable.value] }.compact_blank

            dials['scan_effort'] = scan_effort(dials['scan_effort'])

            # A run that checks out the default branch ingests as a default-branch scan, so it
            # must stay a full scan, even with BL_TARGET_FILES set or a merge request IID goal.
            if primary_branch == project.default_branch_or_main
              dials = dials.except('target_files')
            else
              dials['target_files'] ||= merge_request_target_files
            end

            dials.compact
          end

          private

          attr_reader :project, :primary_branch, :goal

          def scan_effort(value)
            return DEFAULT_SCAN_EFFORT if value.nil?

            normalized = value.strip.downcase
            return normalized if SCAN_EFFORTS.include?(normalized)

            ::Gitlab::AppJsonLogger.info(message: 'Business logic security scan: unknown BL_SCAN_EFFORT, using low',
              project_id: project.id, reason: 'invalid_scan_effort')
            DEFAULT_SCAN_EFFORT
          end

          # nil makes the run a whole-repository scan. The API and Duo Chat take the goal and
          # the branch separately, so the diff is used only on the merge request's source branch.
          def merge_request_target_files
            result = TargetFiles.for_goal(project: project, goal: goal)
            reason = result.reason
            reason = :branch_mismatch if result.paths && result.source_branch != primary_branch

            if reason
              ::Gitlab::AppJsonLogger.info(
                message: 'Business logic security scan target_files omitted, scanning the whole repository',
                project_id: project.id,
                merge_request_iid: goal.to_s,
                reason: reason.to_s
              )
              return
            end

            # Empty only for a deletion-only merge request, whose run the flow's goal
            # validator refuses before it gets here.
            result.paths.presence&.join("\n")
          end
        end
      end
    end
  end
end
