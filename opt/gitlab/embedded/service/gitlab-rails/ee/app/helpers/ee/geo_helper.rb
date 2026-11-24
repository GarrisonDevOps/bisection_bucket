# frozen_string_literal: true

module EE
  module GeoHelper
    STATUS_ICON_NAMES_BY_STATE = {
      synced: 'check-circle-filled',
      pending: 'status_pending',
      failed: 'status_failed',
      never: 'status_notfound'
    }.freeze

    def self.current_node_human_status
      return s_('Geo|primary') if ::Gitlab::Geo.primary?
      return s_('Geo|secondary') if ::Gitlab::Geo.secondary?
      return s_('Geo|org migration target cell') if ::Gitlab::Geo.org_migration_target?

      s_('Geo|misconfigured')
    end

    def replicable_group_items(target_node, replicator_classes)
      replicator_classes.map do |klass|
        {
          title: klass.replicable_title_plural,
          path: site_replicables_admin_geo_node_path(target_node, replicable_name_plural: klass.replicable_name_plural)
        }
      end
    end

    def geo_sites_vue_data
      {
        replicable_types: replicable_types.to_json,
        new_site_url: new_admin_geo_node_path,
        geo_sites_empty_state_svg: image_path("illustrations/empty-state/empty-geo-md.svg"),
        geo_license_allows: ::Gitlab::Geo.license_allows?.to_s,
        manage_subscription_url: admin_subscription_path
      }
    end

    def selective_sync_types_json
      options = {
        ALL: {
          label: s_('Geo|All projects'),
          value: ''
        },
        NAMESPACES: {
          label: s_('Geo|Projects in certain groups'),
          value: 'namespaces'
        },
        SHARDS: {
          label: s_('Geo|Projects in certain storage shards'),
          value: 'shards'
        }
      }

      if ::Gitlab::Geo.geo_selective_sync_by_organizations_enabled?
        options[:ORGANIZATIONS] = {
          label: s_('Geo|Projects in certain organizations'),
          value: 'organizations'
        }
      end

      options.to_json
    end

    def replicable_types
      ::Gitlab::Geo.replication_enabled_replicator_classes
        .map { |replicator_class| replicable_class_data(replicator_class) }
        .sort_by { |data| data[:title] }
    end

    def replicable_class_data(replicator_class)
      {
        data_type: replicator_class.data_type,
        data_type_title: replicator_class.data_type_title,
        data_type_sort_order: replicator_class.data_type_sort_order,
        title: replicator_class.replicable_title,
        title_plural: replicator_class.replicable_title_plural,
        name: replicator_class.replicable_name,
        name_plural: replicator_class.replicable_name_plural,
        graphql_field_name: replicator_class.graphql_field_name,
        graphql_registry_class: replicator_class.registry_class,
        graphql_mutation_registry_class: replicator_class.graphql_mutation_registry_class,
        model_class_name: replicator_class.model.name,
        data_management_url: list_admin_data_management_path(model_name: replicator_class.model_name.pluralize),
        replication_enabled: replicator_class.replication_enabled?,
        verification_enabled: replicator_class.verification_enabled?,
        graphql_registry_id_type: replicator_class.graphql_registry_id_type.to_s,
        replicable_group: replicator_class.replicable_group
      }
    end

    def model_types
      ::Gitlab::Geo::ModelMapper.available_replicable_models
        .map { |model_class| model_type_data(model_class) }
        .sort_by { |data| data[:title] }
    end

    def model_type_data(model_class)
      model_name = ::Gitlab::Geo::ModelMapper.convert_to_name(model_class)
      has_replicator = model_class.respond_to?(:replicator_class)

      {
        title: model_name.titleize,
        title_plural: model_name.titleize.pluralize,
        name: model_name,
        name_plural: model_name.pluralize,
        model_class: model_class.name,
        checksum_enabled: has_replicator ? model_class.replicator_class.verification_enabled? : false
      }
    end

    def data_management_group_items(models)
      models
        .map { |model| model_type_data(model) }
        .sort_by { |data| data[:title_plural] }
        .map do |data|
          { title: data[:title_plural], path: list_admin_data_management_path(model_name: data[:name_plural]) }
        end
    end

    def format_file_size_for_checksum(file_size)
      return file_size if file_size.length.even?

      "0" + file_size
    end

    def admin_data_management_app_data(model_class)
      {
        model_types: model_types.to_json,
        initial_model_type_name: ::Gitlab::Geo::ModelMapper.convert_to_name(model_class).pluralize,
        base_path: admin_data_management_path
      }
    end

    def admin_data_management_item_app_data(model)
      {
        model_type_data: model_type_data(model.class).to_json,
        model_id: model.id.to_s
      }
    end
  end
end
