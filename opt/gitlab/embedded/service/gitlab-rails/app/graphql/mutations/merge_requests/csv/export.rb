# frozen_string_literal: true

module Mutations
  module MergeRequests
    module CSV
      class Export < BaseMutation
        graphql_name 'MergeRequestsCsvExport'

        include FindsProject
        include ::SearchArguments
        include ::MergeRequests::SharedFilterArguments

        authorize :read_merge_request
        authorize_granular_token permissions: :read_merge_request, boundary_argument: :project_path,
          boundary_type: :project

        accept_assignee
        accept_author
        accept_reviewer

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full project path.'

        field :message, GraphQL::Types::String,
          null: true,
          description: 'Export request result message.'

        def resolve(args)
          project_path = args.delete(:project_path)
          project = @resource_parent = authorized_find!(project_path)

          ::Issuables::ScheduleCsvExportService.new(
            type: :merge_request, current_user: current_user, project: project,
            params: prepare_finder_params(args.compact)
          ).execute

          {
            message: format(
              _('Your CSV export request has succeeded. The result will be emailed to %{email}.'),
              { email: current_user.notification_email_or_default }
            ),
            errors: []
          }
        end

        private

        attr_reader :resource_parent
      end
    end
  end
end
