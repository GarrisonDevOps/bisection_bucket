# frozen_string_literal: true

module RemoteDevelopment
  module BlobHelper
    extend ActiveSupport::Concern

    included do
      # noinspection RubyResolve -- Rubymine not finding path helper
      # @return [Hash]
      def vue_blob_workspace_data
        {
          new_workspace_path: new_remote_development_workspace_path,
          organization_id: Current.organization.id
        }
      end
    end
  end
end
