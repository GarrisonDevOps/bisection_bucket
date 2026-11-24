# frozen_string_literal: true

module Ai
  module DuoSettings
    # Shared by the `duo_auto_mode` capability and the promote list, so they agree for a scope.
    module AutoMode
      def self.consented?(container:)
        return false unless container
        return false unless Feature.enabled?(:duo_auto_mode, container.root_ancestor)

        project = container if container.is_a?(::Project)

        CascadingSettingResolver.enabled?(
          project: project, namespace: project ? nil : container, attribute: :duo_auto_mode_enabled?
        )
      end
    end
  end
end
