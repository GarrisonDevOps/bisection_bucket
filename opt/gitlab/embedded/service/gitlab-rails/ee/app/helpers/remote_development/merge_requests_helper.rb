# frozen_string_literal: true

module RemoteDevelopment
  module MergeRequestsHelper
    extend ActiveSupport::Concern

    included do
      # Creates URL to open workspace for a specific project and ref
      # @param [String] project_path Path of the project of the to-be created workspace
      # @param [String] ref Ref of the project that needs to be opened in the workspace
      def workspace_path_with_params(project_path:, ref:)
        raise unless project_path && ref

        # noinspection RubyResolve -- RubyMine can't find the helper function
        "#{new_remote_development_workspace_path}?project=#{CGI.escape(project_path)}&gitRef=#{ref}"
      end
    end
  end
end
