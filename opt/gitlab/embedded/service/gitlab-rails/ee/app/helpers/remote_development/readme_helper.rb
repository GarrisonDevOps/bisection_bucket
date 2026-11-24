# frozen_string_literal: true

module RemoteDevelopment
  module ReadmeHelper
    extend ActiveSupport::Concern

    included do
      # noinspection RubyResolve -- Rubymine not finding path helper
      # @return [Hash]
      def vue_readme_header_additional_data
        {
          new_workspace_path: new_remote_development_workspace_path,
          organization_id: Current.organization.id
        }
      end
    end
  end
end
