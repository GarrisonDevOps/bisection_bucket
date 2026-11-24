# frozen_string_literal: true

module Mutations
  module WorkItems
    module CSV
      class Export < BaseMutation
        graphql_name 'WorkItemsCsvExport'

        include FindsProject
        include ::SearchArguments
        include ::WorkItems::SharedFilterArguments

        authorize :export_work_items
        authorize_granular_token permissions: :read_work_item, boundary_argument: :project_path,
          boundary_type: :project

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full project path.'

        argument :selected_fields, [::Types::WorkItems::AvailableExportFieldsEnum],
          required: false,
          description: 'List of selected fields to be exported. Omit to export all available fields.'

        field :message, GraphQL::Types::String,
          null: true,
          description: 'Export request result message.'

        def resolve(args)
          project_path = args.delete(:project_path)
          project = authorized_find!(project_path)

          ::Issuables::ScheduleCsvExportService.new(
            type: :work_item, current_user: current_user, project: project, params: prepare_finder_params(args)
          ).execute

          {
            message: format(
              _('Your CSV export request has succeeded. The result will be emailed to %{email}.'),
              { email: current_user.notification_email_or_default }
            ),
            errors: []
          }
        end
      end
    end
  end
end

Mutations::WorkItems::CSV::Export.prepend_mod
