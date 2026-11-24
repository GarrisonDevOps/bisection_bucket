# frozen_string_literal: true

module Mutations
  module Security
    module Attributes
      class BulkUpdate < BaseMutation
        graphql_name 'BulkUpdateSecurityAttributes'

        authorize :admin_security_attributes

        MAX_ITEMS = 100
        MAX_ATTRIBUTES = 20

        argument :items, [GraphQL::Types::ID],
          required: true,
          description: 'Global IDs of groups and projects to update.',
          prepare: ->(global_ids, _ctx) {
            if global_ids.size > MAX_ITEMS
              raise Gitlab::Graphql::Errors::ArgumentError, "Too many items (maximum: #{MAX_ITEMS})"
            end

            GitlabSchema.parse_gids(global_ids, expected_type: [Group, Project])
          }

        argument :attributes, [::Types::GlobalIDType[::Security::Attribute]],
          required: true,
          description: 'Global IDs of security attributes to apply.'

        argument :mode, Types::Security::Attributes::BulkUpdateModeEnum,
          required: true,
          description: 'Update mode: add, remove, or replace attributes.'

        field :errors, [GraphQL::Types::String],
          null: false,
          description: 'Errors encountered while initiating the bulk update operation.'

        def resolve(items:, attributes:, mode:)
          validate_arguments!(items, attributes)

          security_attributes = authorized_security_attributes(attributes)

          grouped_items = items.group_by { |gid| gid.model_class.name }
          group_ids = grouped_items.fetch('Group', []).map { |item| item.model_id.to_i }.uniq
          project_ids = grouped_items.fetch('Project', []).map { |item| item.model_id.to_i }.uniq

          authorize_items!(group_ids, project_ids, security_attributes)

          result = ::Security::Attributes::BulkUpdateService.new(
            group_ids: group_ids,
            project_ids: project_ids,
            attribute_ids: security_attributes.map(&:id),
            mode: mode,
            current_user: current_user
          ).execute

          {
            errors: result.success? ? [] : [result.message]
          }
        rescue Gitlab::Access::AccessDeniedError
          raise_resource_not_available_error!
        end

        private

        def validate_arguments!(items, attributes)
          raise Gitlab::Graphql::Errors::ArgumentError, 'Items cannot be empty' if items.empty?
          raise Gitlab::Graphql::Errors::ArgumentError, 'Attributes cannot be empty' if attributes.empty?

          return unless attributes.size > MAX_ATTRIBUTES

          raise Gitlab::Graphql::Errors::ArgumentError, "Too many attributes (maximum: #{MAX_ATTRIBUTES})"
        end

        def authorized_security_attributes(attribute_gids)
          attribute_gids.map do |gid|
            attribute = authorized_find!(id: GitlabSchema.parse_gid(gid, expected_type: ::Security::Attribute))

            raise_resource_not_available_error! if attribute.deleted?

            attribute
          end
        end

        # Attributes are always owned by a root namespace, and Security::ProjectToSecurityAttribute
        # rejects any association that crosses one.
        def attributes_root_namespace_id(security_attributes)
          namespace_ids = security_attributes.map(&:namespace_id).uniq

          if namespace_ids.size > 1
            raise Gitlab::Graphql::Errors::ArgumentError, 'Attributes must belong to the same namespace'
          end

          namespace_ids.first
        end

        # Authorizing up front stops a group the user can read but not administer, or one outside the
        # attributes' root namespace, from being fanned out into a job per 50 projects that all fail.
        def authorize_items!(group_ids, project_ids, security_attributes)
          root_namespace_id = attributes_root_namespace_id(security_attributes)

          # Loaded here so the size guards below cost no extra query, and kept as relations:
          # ProjectPolicyPreloader skips its root ancestor preload for anything else.
          groups = Group.id_in(group_ids).load
          projects = Project.id_in(project_ids).include_project_feature.load

          raise_resource_not_available_error! unless groups.size == group_ids.size
          raise_resource_not_available_error! unless projects.size == project_ids.size

          # Without these the policy checks cost five queries per project.
          Preloaders::GroupPolicyPreloader.new(groups, current_user).execute
          Preloaders::ProjectPolicyPreloader.new(projects, current_user).execute

          (groups.to_a + projects.to_a).each { |item| authorize!(item) }

          # Compared after authorization so the error cannot reveal items in other namespaces.
          item_root_namespace_ids = groups.map { |group| group.traversal_ids.first } |
            projects.map { |project| project.namespace.traversal_ids.first }

          return if item_root_namespace_ids == [root_namespace_id]

          raise Gitlab::Graphql::Errors::ArgumentError,
            'Items must belong to the same namespace as the attributes'
        end
      end
    end
  end
end
