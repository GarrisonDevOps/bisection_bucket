# frozen_string_literal: true

module Mutations
  module Security
    module Attributes
      class ProjectUpdate < BaseMutation
        graphql_name 'SecurityAttributeProjectUpdate'

        authorize :admin_security_attributes
        authorize_granular_token permissions: :update_security_attribute,
          boundary_argument: :project_id, boundary_type: :project

        argument :project_id, ::Types::GlobalIDType[::Project],
          required: true,
          description: 'Global ID of the project.'

        argument :add_attribute_ids, [::Types::GlobalIDType[::Security::Attribute]],
          required: false,
          description: 'Global IDs of the security attributes to add to the project.',
          prepare: ->(gids, _) { GitlabSchema.parse_gids(gids, expected_type: ::Security::Attribute).map(&:model_id) }

        argument :remove_attribute_ids, [::Types::GlobalIDType[::Security::Attribute]],
          required: false,
          description: 'Global IDs of the security attributes to remove from the project.',
          prepare: ->(gids, _) { GitlabSchema.parse_gids(gids, expected_type: ::Security::Attribute).map(&:model_id) }

        field :added_count, GraphQL::Types::Int,
          null: true,
          description: 'Number of attributes added.'

        field :project, Types::ProjectType,
          null: true,
          description: 'Updated project.'

        field :removed_count, GraphQL::Types::Int,
          null: true,
          description: 'Number of attributes removed.'

        def resolve(project_id:, add_attribute_ids: [], remove_attribute_ids: [])
          project = authorized_find!(id: project_id)

          parsed_add_ids = parse_attribute_ids(add_attribute_ids, project)
          return error_response(parsed_add_ids[:errors]) if parsed_add_ids[:errors].present?

          if no_attributes_to_process?(parsed_add_ids[:attribute_ids], remove_attribute_ids)
            return error_response(['No attributes found for addition or removal'])
          end

          execute_update_service(project, parsed_add_ids[:attribute_ids], remove_attribute_ids)
        end

        private

        def parse_attribute_ids(add_attribute_ids, project)
          return { attribute_ids: [], errors: [] } if add_attribute_ids.blank?

          valid_template_types = Enums::Security.attributes_template_types.keys.map(&:to_s)
          persisted_ids, template_types = add_attribute_ids.partition { |id| valid_template_types.exclude?(id) }
          all_attribute_ids = persisted_ids.map(&:to_i)

          if template_types.present?
            template_result = process_template_types(template_types, project.namespace.root_ancestor)
            return template_result if template_result[:errors].present?

            all_attribute_ids.concat(template_result[:attribute_ids])
          end

          { attribute_ids: all_attribute_ids.uniq, errors: [] }
        end

        def process_template_types(template_types, namespace)
          predefined_result = create_predefined_attributes(namespace)
          return { attribute_ids: [], errors: [predefined_result.message] } unless predefined_result.success?

          attribute_ids = fetch_attribute_ids_by_template_types(template_types, namespace)
          { attribute_ids: attribute_ids, errors: [] }
        end

        def create_predefined_attributes(namespace)
          ::Security::Categories::CreatePredefinedService.new(namespace: namespace, current_user: current_user).execute
        end

        def fetch_attribute_ids_by_template_types(template_types, namespace)
          ::Security::Attribute.by_namespace(namespace.id).by_template_type(template_types).pluck_id
        end

        def no_attributes_to_process?(add_ids, remove_ids)
          add_ids.empty? && remove_ids.empty?
        end

        def execute_update_service(project, add_ids, remove_ids)
          result = ::Security::Attributes::UpdateProjectAttributesService.new(
            project: project,
            current_user: current_user,
            params: {
              attributes: {
                add_attribute_ids: add_ids,
                remove_attribute_ids: remove_ids
              }
            }
          ).execute

          result.success? ? success_response(result.payload) : error_response([result.message])
        end

        def success_response(payload)
          {
            project: payload[:project],
            added_count: payload[:added_count],
            removed_count: payload[:removed_count],
            errors: []
          }
        end

        def error_response(errors)
          {
            project: nil,
            added_count: nil,
            removed_count: nil,
            errors: errors
          }
        end
      end
    end
  end
end
