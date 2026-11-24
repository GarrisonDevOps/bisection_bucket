# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoSettings
      # Returns the admin Duo-availability view of groups: each group with its
      # effective/inherited availability, admin-lock flag and locking ancestor.
      #
      # Availability derivation needs each group's ancestor chain. To avoid an
      # N+1 on NamespaceSetting we page the groups first, then batch-load every
      # relevant NamespaceSetting (groups + their ancestors) in one query and
      # hand a shared id->setting map to the presenter.
      class DuoAvailabilityNamespacesResolver < BaseResolver
        include ::Gitlab::Graphql::Authorize::AuthorizeResource

        authorize :read_namespace_duo_availability

        type Types::Ai::DuoSettings::DuoAvailabilityNamespaceType.connection_type, null: true

        argument :parent_id, ::Types::GlobalIDType[::Group],
          required: false,
          description: 'Restrict the list to descendants of the given group.'

        argument :include_descendants, GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          description: 'Include all descendants, not just direct children, of the parent group.'

        argument :admin_locked, GraphQL::Types::Boolean,
          required: false,
          description: 'Filter to groups that are (or are not) the introducer of an admin lock.'

        argument :duo_availability, [::Types::Ai::DuoSettings::DuoAvailabilityEnum],
          required: false,
          description: 'Filter to groups whose effective availability is one of these values.'

        argument :search, GraphQL::Types::String,
          required: false,
          description: 'Filter groups by name or full path.'

        def resolve(parent_id: nil, include_descendants: false, admin_locked: nil, duo_availability: nil, search: nil)
          authorize!(:global)

          groups = base_groups(parent_id: parent_id, include_descendants: include_descendants)
          groups = groups.search(search) if search.present?

          presenters = present(groups.to_a)

          # Filtering happens in Ruby, so we return a plain Array; the schema maps
          # Array to ArrayConnection, which handles cursor pagination. offset_pagination
          # cannot be used here as it expects an ActiveRecord::Relation.
          filter(presenters, admin_locked: admin_locked, duo_availability: duo_availability)
        end

        private

        def base_groups(parent_id:, include_descendants:)
          return ::Group.order_id_asc if parent_id.blank?

          parent = ::Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(parent_id))
          return ::Group.none unless parent

          include_descendants ? parent.descendants.order_id_asc : parent.children.order_id_asc
        end

        # Builds one presenter per group, sharing a single id->NamespaceSetting
        # map covering the groups and every ancestor namespace id.
        def present(groups)
          return [] if groups.empty?

          namespace_ids = groups.flat_map(&:traversal_ids).uniq
          settings_by_id = ::NamespaceSetting
            .for_namespaces(namespace_ids)
            .with_namespace
            .index_by(&:namespace_id)

          instance_default = ::Gitlab::CurrentSettings.duo_availability.to_s

          groups.map do |group|
            ::Ai::DuoSettings::DuoAvailabilityNamespacePresenter.new(
              group,
              settings_by_namespace_id: settings_by_id,
              instance_default: instance_default
            )
          end
        end

        def filter(presenters, admin_locked:, duo_availability:)
          presenters = presenters.select { |presenter| presenter.admin_locked == admin_locked } unless admin_locked.nil?

          if duo_availability.present?
            wanted = Array(duo_availability).map(&:to_s).to_set
            presenters = presenters.select { |presenter| wanted.include?(presenter.duo_availability) }
          end

          presenters
        end
      end
    end
  end
end
