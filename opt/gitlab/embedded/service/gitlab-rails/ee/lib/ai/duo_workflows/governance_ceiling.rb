# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module GovernanceCeiling
      module_function

      # Flag state is not inherited, so every ancestor group is checked to let the flag be
      # enabled for a subgroup. Enabling it anywhere can only make a session stricter.
      def enabled?(container)
        namespace = container.is_a?(::Project) ? container.namespace : container
        return false unless namespace

        # A user namespace gates as itself, not as a Group.
        unless namespace.is_a?(::Group)
          return Feature.enabled?(:duo_workflow_governance_ceiling, namespace.root_ancestor)
        end

        namespace.traversal_ids.any? do |id|
          Feature.enabled?(:duo_workflow_governance_ceiling, ::Group.actor_from_id(id))
        end
      end
    end
  end
end
