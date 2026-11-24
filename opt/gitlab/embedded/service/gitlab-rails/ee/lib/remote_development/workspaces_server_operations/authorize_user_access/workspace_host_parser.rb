# frozen_string_literal: true

module RemoteDevelopment
  module WorkspacesServerOperations
    module AuthorizeUserAccess
      class WorkspaceHostParser
        include Messages
        extend Gitlab::Fp::MessageSupport

        # NOTE: If any changes are made to the URL parsing, ensure the same is reflected in
        #       `ee/lib/remote_development/workspace_operations/workspace_url_helper.rb`.

        # Parse the workspace host to extract port and workspace name
        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.parse_workspace_host(context)
          context => {
            workspace_host: String => workspace_host
          }

          # Parse the workspace host to extract port and workspace name
          # Expected format: port-workspace_name.domain.com
          begin
            # If workspace_host looks like a URL, extract just the host part
            if workspace_host.include?('://')
              parsed_uri = URI.parse(workspace_host)
              hostname = parsed_uri.host
            else
              hostname = workspace_host
            end

            # Validate hostname is present
            if hostname.blank?
              return Gitlab::Fp::Result.err(
                WorkspaceAuthorizeUserAccessFailed.new({ status: Status::INVALID_HOST })
              )
            end

            # Extract the subdomain part (everything before the first dot)
            subdomain = hostname.split('.', 2).first
            # Split subdomain into port and workspace name
            port, workspace_name = subdomain.split('-', 2)

            # Validate that we have both port and workspace name
            if port.blank? || workspace_name.blank?
              return Gitlab::Fp::Result.err(
                WorkspaceAuthorizeUserAccessFailed.new({ status: Status::INVALID_HOST })
              )
            end

            # Add the parsed values to context
            Gitlab::Fp::Result.ok(
              context.merge(
                port: port,
                workspace_name: workspace_name
              )
            )
          rescue URI::InvalidURIError, StandardError
            Gitlab::Fp::Result.err(
              WorkspaceAuthorizeUserAccessFailed.new({ status: Status::INVALID_HOST })
            )
          end
        end
      end
    end
  end
end
