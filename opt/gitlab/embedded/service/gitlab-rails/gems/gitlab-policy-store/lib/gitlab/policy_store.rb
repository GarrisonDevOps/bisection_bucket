# frozen_string_literal: true

require_relative "policy_store/version"
require_relative "policy_store/triggers"
require_relative "policy_store/roles"
require_relative "policy_store/actions"
require_relative "policy_store/rules"
require_relative "policy_store/policy"
require_relative "policy_store/page"
require_relative "policy_store/json_value"
require_relative "policy_store/json_bytesize"
require_relative "policy_store/scope_transpiler"
require_relative "policy_store/rego_package"
require_relative "policy_store/rule_transpiler/invalidates_via_callable"
require_relative "policy_store/rule_transpiler/authored_instant"
require_relative "policy_store/rule_transpiler/emitters/base"
require_relative "policy_store/rule_transpiler/emitters/custom"
require_relative "policy_store/rule_transpiler/emitters/environment"
require_relative "policy_store/rule_transpiler/emitters/calendar"
require_relative "policy_store/rule_transpiler/emitters/setting_validation"
require_relative "policy_store/rule_transpiler"
require_relative "policy_store/rule_program_merger"
require_relative "policy_store/rego_validator"
require_relative "policy_store/violation"
require_relative "policy_store/evaluation"
require_relative "policy_store/enumerated_attribute_validation"
require_relative "policy_store/action_shape_validation"
require_relative "policy_store/role_validation"
require_relative "policy_store/ports/policy_repository"
require_relative "policy_store/ports/evaluation_recorder"
require_relative "policy_store/configuration"

module Gitlab
  # Public facade for the Policy Store component.
  #
  # This is the ONLY entry point callers should use. Everything behind it is
  # internal. All persistence goes through injectable ports (a
  # Gitlab::PolicyStore::Ports::PolicyRepository for policies, a
  # Gitlab::PolicyStore::Ports::EvaluationRecorder for evaluation results), so
  # the in-monolith backends used today can be swapped for a remote service
  # later without changing any caller.
  module PolicyStore
    # Domain errors are defined here so callers never need to rescue persistence-
    # or transport-specific exceptions across the component boundary.
    Error = Class.new(StandardError)
    NotFound = Class.new(Error)
    ValidationError = Class.new(Error)
    # Raised when the Rego engine itself fails.
    EngineError = Class.new(Error)
    # Deliberately not a domain error: a host that configured no adapter has no storage,
    # and a caller rescuing Error across the boundary must not swallow that.
    NotConfigured = Class.new(StandardError)

    class << self
      def configure
        yield(configuration)
      end

      def configuration
        @configuration ||= Configuration.new
      end

      # Discards the configured backends. Intended for specs: in GitLab the backends are
      # configured from an initializer, so nothing restores them until a code reload, and
      # every facade call raises NotConfigured until then.
      def reset_configuration!
        @configuration = nil
      end

      def create(attributes)
        repository.create(attributes)
      end

      def update(id, attributes)
        repository.update(id, attributes)
      end

      def find(id)
        repository.find(id)
      end

      def delete(id)
        repository.delete(id)
      end

      def list(
        organization_id:, trigger_type: nil, namespace_ids: nil, lifecycle_state: nil, ids: nil, offset: 0,
        per_page: Ports::PolicyRepository::DEFAULT_PER_PAGE)
        repository.list(
          organization_id: organization_id, trigger_type: trigger_type, namespace_ids: namespace_ids,
          lifecycle_state: lifecycle_state, ids: ids, offset: offset, per_page: per_page
        )
      end

      def record_evaluation(attributes)
        evaluation_recorder.record(attributes)
      end

      private

      def repository
        configuration.repository || raise(NotConfigured, 'No policy repository: call Gitlab::PolicyStore.configure')
      end

      def evaluation_recorder
        configuration.evaluation_recorder ||
          raise(NotConfigured, 'No evaluation recorder: call Gitlab::PolicyStore.configure')
      end
    end
  end
end
