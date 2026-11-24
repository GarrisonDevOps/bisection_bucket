# frozen_string_literal: true

module Govern
  module PolicyEngine
    module Impact
      # Tells whether the host resolver covers a policy_scope document exactly.
      # The resolver over-approximates on purpose, because the engine applies
      # the compiled scope afterwards. A dry run has no second pass, so a scope
      # the resolver cannot cover exactly is reported as unavailable rather than
      # over-counted.
      module ScopeSupport
        MATCH_MODE_KEY = 'match_mode'
        MATCH_ANY = 'any'

        def self.unsupported_reason(policy_scope, scope_rego: nil)
          return :scope_rego if scope_rego.present?

          scope = policy_scope.try(:deep_stringify_keys) || {}

          return :security_attributes if attribute_dimension?(scope)

          inclusions = declared_inclusions(scope)
          # rubocop:disable CodeReuse/ActiveRecord -- ScopeCriterion#ids is a plain reader, not a query
          return :empty_inclusion if inclusions.any? { |list| ScopeCriterion.from(list).ids.empty? }
          # rubocop:enable CodeReuse/ActiveRecord
          # The compiled scope intersects inclusion dimensions unless match_mode is
          # "any"; the resolver always unions them.
          return :combined_inclusions if inclusions.size > 1 && scope[MATCH_MODE_KEY] != MATCH_ANY

          nil
        end

        # Whether the resolver serves the scope from one inclusion arm. Each arm
        # yields ascending ids, so a single-arm read can stop once the cap is passed.
        def self.single_arm?(policy_scope)
          declared_inclusions(policy_scope.try(:deep_stringify_keys) || {}).size <= 1
        end

        def self.attribute_dimension?(scope)
          ::Gitlab::PolicyStore::ScopeTranspiler::ATTRIBUTE_DIMENSIONS.any? do |attribute|
            dimension = scope[attribute[:field]]

            dimension.is_a?(Hash) && dimension.values_at(ScopedProjectsResolver::INCLUDING,
              ScopedProjectsResolver::EXCLUDING).any?(&:present?)
          end
        end
        private_class_method :attribute_dimension?

        # The inclusion lists the document declares, in the shape the resolver reads
        # them: projects and groups under `including`, compliance frameworks flat.
        def self.declared_inclusions(scope)
          nested = [ScopedProjectsResolver::PROJECTS, ScopedProjectsResolver::GROUPS].filter_map do |dimension|
            lists = scope[dimension]
            lists[ScopedProjectsResolver::INCLUDING] if lists.is_a?(Hash)
          end

          [*nested, scope[ScopedProjectsResolver::COMPLIANCE_FRAMEWORKS]].select { |list| list.is_a?(Array) && list.any? }
        end
        private_class_method :declared_inclusions
      end
    end
  end
end
