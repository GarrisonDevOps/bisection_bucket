# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module Concerns
      # Shared retry wrapper around Ai::ToolRules::ResolutionService so every
      # governance clamp site tolerates the same transient failures before its
      # caller decides how to fail.
      module GovernanceResolution
        MAX_GOVERNANCE_RETRIES = 3

        private

        # Clamping an unknown privilege hides it; let model validation report it.
        def known_privileges?(*sets)
          sets.compact.flatten.all? do |privilege|
            ::Ai::DuoWorkflows::Workflow::AgentPrivileges::ALL_PRIVILEGES.key?(privilege)
          end
        end

        # Executes the resolution service, retrying transient failures.
        # Returns the last ServiceResponse; a failed response is returned
        # as-is so the caller chooses its own failure mode.
        def resolve_governance_with_retry(service, **log_context)
          result = nil

          MAX_GOVERNANCE_RETRIES.times do |attempt|
            result = service.execute
            break if result.success?

            # Retrying cannot change a surface, and the caller logs this case.
            break if result.reason == :ungoverned_surface

            Gitlab::AppLogger.warn(
              message: "Governance resolution failed, retrying (attempt #{attempt + 1}/#{MAX_GOVERNANCE_RETRIES})",
              **log_context
            )
          end

          result
        end

        # The loop breaks on the first ungoverned result, so a retry count would be a lie.
        def governance_failure_message(outcome, result)
          return "Governance resolution skipped for an ungoverned surface, #{outcome}" if
            result&.reason == :ungoverned_surface

          "Governance resolution failed after #{MAX_GOVERNANCE_RETRIES} retries, #{outcome}"
        end
      end
    end
  end
end
