# frozen_string_literal: true

module Mutations
  module WorkItems
    module Settings
      class Update < BaseMutation
        graphql_name 'WorkItemSettingsUpdate'
        description 'Updates work item settings for a root group or organization. ' \
          'Omit fullPath to update settings for the current organization.'

        include Mutations::ResolvesGroup
        include Mutations::WorkItems::RequiresFullPathForGranularTokens

        authorize :update_work_item_setting
        authorize_granular_token permissions: :update_work_item_setting, boundary_argument: :full_path,
          boundary_type: :group

        argument :full_path, GraphQL::Types::ID,
          required: false,
          description: 'Full path of the root group. Omit to use the current organization.'

        argument :customizable_type_visibility, GraphQL::Types::Boolean,
          required: false,
          description: 'Whether namespace admins can configure per-type work item visibility.'

        field :work_item_settings, ::Types::WorkItems::SettingsType,
          null: true,
          description: 'Work item settings after mutation.'

        def resolve(full_path: nil, **args)
          container = authorized_find!(full_path: full_path)

          settings = ::WorkItems::Settings.for_namespace(container)
          settings.assign_attributes(args)

          if settings.save
            success_response(settings)
          else
            error_response(settings)
          end
        rescue ActiveRecord::RecordNotUnique
          retry_due_to_conflict(container, args)
        end

        private

        def find_object(full_path:)
          full_path.present? ? resolve_group(full_path: full_path) : context[:current_organization]
        end

        def success_response(settings)
          { work_item_settings: settings, errors: [] }
        end

        def error_response(settings)
          { work_item_settings: nil, errors: errors_on_object(settings) }
        end

        def retry_due_to_conflict(container, args)
          settings = ::WorkItems::Settings.for_namespace(container)

          if settings.update(args)
            success_response(settings)
          else
            error_response(settings)
          end
        end
      end
    end
  end
end
