# frozen_string_literal: true

module Mutations
  module MergeRequests
    class ResolveConflicts < Base
      graphql_name 'MergeRequestResolveConflicts'
      description 'Resolves the conflicts of a merge request the way the web UI does: ' \
        'commits a merge of the target branch into the source branch.'

      authorize_granular_token permissions: :update_merge_request, boundary_argument: :project_path,
        boundary_type: :project

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      argument :commit_message, GraphQL::Types::String,
        required: false,
        description: 'Message of the merge commit. Defaults to the message the web UI uses.'

      argument :files, [Types::MergeRequests::ConflictFileResolutionInputType],
        required: true,
        validates: { length: { maximum: Types::BaseArgument::MAX_ARRAY_SIZE } },
        description: 'Resolution of every file in `MergeRequest.conflictFiles`. ' \
          "Maximum is #{Types::BaseArgument::MAX_ARRAY_SIZE} files."

      def resolve(project_path:, iid:, files:, commit_message: nil)
        merge_request = authorized_find!(project_path: project_path, iid: iid)

        result = ::MergeRequests::Conflicts::ResolveService
          .new(merge_request)
          .execute(current_user, commit_message: commit_message, files: files.map { |file| service_file(file) })

        {
          merge_request: merge_request,
          errors: result.errors
        }
      end

      private

      # The web UI's shape: old_path is the target side, new_path the source side
      def service_file(file)
        paths = { old_path: file[:their_path], new_path: file[:our_path] }
        return paths.merge(content: file[:content]) if file[:content]

        paths.merge(sections: sections_by_id(file))
      end

      # The web UI posts a hash, but this list can name a section twice and to_h would keep only the last
      def sections_by_id(file)
        duplicate_id, = file[:sections].map { |section| section[:section_id] }.tally.find { |_id, count| count > 1 }

        if duplicate_id
          raise Gitlab::Graphql::Errors::ArgumentError,
            "File #{file[:our_path]} has more than one resolution for section #{duplicate_id}."
        end

        file[:sections].to_h { |section| [section[:section_id], section[:resolution]] }
      end
    end
  end
end
