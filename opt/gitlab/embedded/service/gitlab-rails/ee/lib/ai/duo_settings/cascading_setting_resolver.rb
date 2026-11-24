# frozen_string_literal: true

module Ai
  module DuoSettings
    # Resolves a boolean cascading Duo setting with project-wins-over-namespace
    # precedence, shared by the capability-advertisement paths (the REST
    # `direct_access` endpoint and FlowsMetadataService) so they cannot drift.
    # Callers resolve `project` themselves first, since the API path scopes it to
    # a readable project inside the namespace before passing it here. `attribute`
    # names the predicate on the project_setting/namespace_settings object.
    module CascadingSettingResolver
      def self.enabled?(project:, namespace:, attribute:)
        # rubocop:disable GitlabSecurity/PublicSend -- attribute is a literal symbol from internal callers, never user input
        return !!project.project_setting&.public_send(attribute) if project

        !!namespace&.namespace_settings&.public_send(attribute)
        # rubocop:enable GitlabSecurity/PublicSend
      end
    end
  end
end
