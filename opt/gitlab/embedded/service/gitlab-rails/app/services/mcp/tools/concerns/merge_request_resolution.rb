# frozen_string_literal: true

module Mcp
  module Tools
    module Concerns
      # Shared url-or-ids merge request lookup. Host must provide `current_user`
      # and include ResourceFinder (for find_project).
      module MergeRequestResolution
        private

        def resolve_merge_request!(args)
          if args[:url].present?
            match = ::MergeRequest.link_reference_pattern.match(args[:url])
            raise ArgumentError, "Invalid merge request URL: #{args[:url]}" unless match

            project = find_project("#{match[:namespace]}/#{match[:project]}")
            iid = match[:merge_request].to_i
          else
            iid = args[:merge_request_iid]
            unless iid && args[:project_id].present?
              raise ArgumentError, 'Provide either url, or project_id and merge_request_iid'
            end

            project = find_project(args[:project_id])
          end

          merge_request = project && ::MergeRequestsFinder.new(
            current_user,
            project_id: project.id,
            iids: [iid]
          ).execute.first

          return merge_request if merge_request

          message = 'Merge request not found or inaccessible'
          raise ResourceFinder::ResourceForbiddenError, message if project&.merge_requests&.exists?(iid: iid)

          raise ResourceFinder::ResourceNotFoundError, message
        end

        # Rejects identifier arguments that conflict with the merge request resolved from the url.
        #
        # @param args [Hash] the tool arguments
        # @param merge_request [MergeRequest] the merge request resolved from args
        # @return [void]
        # @raise [ArgumentError] if an identifier conflicts with the url
        # @note Call after {#resolve_merge_request!}, which lets the url win.
        def validate_url_identification!(args, merge_request)
          return if args[:url].blank?

          iid = args[:merge_request_iid]
          if iid.present? && iid.to_i != merge_request.iid
            raise ArgumentError, 'merge_request_iid does not match the merge request in url'
          end

          return if args[:project_id].blank?

          project = find_project(args[:project_id])
          return if project && project.id == merge_request.project_id

          raise ArgumentError, 'project_id does not match the merge request in url'
        end
      end
    end
  end
end
