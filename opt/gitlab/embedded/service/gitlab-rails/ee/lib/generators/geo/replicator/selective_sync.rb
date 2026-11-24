# frozen_string_literal: true

module Geo
  module Replicator
    # Builds the selective-sync scope body, the sharding-key scope, and the model-spec selective
    # sync fixtures for a replicable, keyed on its sharding key. Pure logic, unit-testable.
    class SelectiveSync
      def initialize(sharding_key:, file_name:, parent_model_factory_name:)
        @sharding_key = sharding_key
        @file_name = file_name
        @parent_model_factory_name = parent_model_factory_name
      end

      def scope_definition
        return '' if @sharding_key.nil?

        {
          'project_id' => 'scope :project_id_in, ->(ids) { where(project_id: ids) }',
          'namespace_id' => 'scope :namespace_id_in, ->(ids) { where(namespace_id: ids) }',
          'organization_id' => 'scope :organization_id_in, ->(ids) { where(organization_id: ids) }',
          'uploaded_by_user_id' => 'scope :uploaded_by_user_id_in, ->(ids) { where(uploaded_by_user_id: ids) }'
        }.fetch(@sharding_key) { unsupported_sharding_key! }
      end

      # Returns the body of selective_sync_scope, each line indented 8 spaces so the model
      # template can interpolate it at column 0 (inside module > class > class << self > def).
      def selective_sync_scope_body
        indent_lines(raw_selective_sync_scope_body, 8)
      end

      # Returns the let/let_it_be fixtures block for the model spec, indented 6 spaces.
      def selective_sync_fixtures
        indent_lines(raw_selective_sync_fixtures, 6)
      end

      def raw_selective_sync_scope_body
        case @sharding_key
        when nil
          <<~RUBY
            replicables = params.fetch(:replicables, all)
            replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

            # Instance-wide cell-setting replicables have no organization, namespace, or
            # project, so they are always replicated regardless of the node's selective
            # sync configuration.
            replicables
          RUBY
        when 'project_id'
          <<~RUBY
            replicables = params.fetch(:replicables, all)
            replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

            return replicables unless node.selective_sync?

            if node.selective_sync_by_namespaces? || node.selective_sync_by_shards?
              replicables.project_id_in(::Project.selective_sync_scope(node).select(:id))
            elsif node.selective_sync_by_organizations?
              organization_ids = node.organizations.select(:id)
              project_ids = ::Project.where(organization_id: organization_ids).select(:id)
              replicables.where(project_id: project_ids)
            else
              raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
            end
          RUBY
        when 'namespace_id'
          <<~RUBY
            replicables = params.fetch(:replicables, all)
            replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

            return replicables unless node.selective_sync?

            if node.selective_sync_by_namespaces? || node.selective_sync_by_shards?
              replicables.namespace_id_in(node.namespaces_for_group_owned_replicables.select(:id))
            elsif node.selective_sync_by_organizations?
              organization_ids = node.organizations.select(:id)
              namespace_ids = ::Namespace.where(organization_id: organization_ids).select(:id)
              replicables.where(namespace_id: namespace_ids)
            else
              raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
            end
          RUBY
        when 'organization_id'
          <<~RUBY
            replicables = params.fetch(:replicables, all)
            replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

            return replicables unless node.selective_sync?

            if node.selective_sync_by_namespaces? || node.selective_sync_by_shards?
              namespace_ids = node.namespaces_for_group_owned_replicables.select(:id)
              organization_ids = ::Namespace.id_in(namespace_ids).distinct(:organization_id).select(:organization_id)
              replicables.organization_id_in(organization_ids)
            elsif node.selective_sync_by_organizations?
              replicables.organization_id_in(node.organizations.select(:id))
            else
              raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
            end
          RUBY
        when 'uploaded_by_user_id'
          <<~RUBY
            replicables = params.fetch(:replicables, all)
            replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

            return replicables unless node.selective_sync?

            if node.selective_sync_by_namespaces? || node.selective_sync_by_shards?
              namespace_ids = node.namespaces_for_group_owned_replicables.select(:id)
              user_ids = ::Member.where(source_type: 'Namespace', source_id: namespace_ids).select(:user_id)
              replicables.uploaded_by_user_id_in(user_ids)
            elsif node.selective_sync_by_organizations?
              organization_ids = node.organizations.select(:id)
              user_ids = ::Organizations::OrganizationUser.in_organization(organization_ids).select(:user_id)
              replicables.uploaded_by_user_id_in(user_ids)
            else
              raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
            end
          RUBY
        else
          unsupported_sharding_key!
        end
      end

      private

      def indent_lines(body, spaces)
        pad = ' ' * spaces
        body.chomp.lines.map { |l| l.strip.empty? ? "\n" : "#{pad}#{l}" }.join
      end

      def unsupported_sharding_key!
        raise ArgumentError, "Unsupported sharding key: #{@sharding_key.inspect}. Expected one of: " \
          'project_id, namespace_id, organization_id, uploaded_by_user_id'
      end

      def raw_selective_sync_fixtures
        case @sharding_key
        when nil then ''
        when 'organization_id' then selective_sync_fixtures_for_organization_id
        when 'namespace_id' then selective_sync_fixtures_for_namespace_id
        when 'project_id' then selective_sync_fixtures_for_project_id
        when 'uploaded_by_user_id' then selective_sync_fixtures_for_uploaded_by_user_id
        else unsupported_sharding_key!
        end
      end

      def selective_sync_fixtures_for_organization_id
        <<~RUBY
          let_it_be(:organization_1) { create(:organization) }
          let_it_be(:organization_2) { create(:organization) }
          let_it_be(:group_1) { create(:group, organization: organization_1) }
          let_it_be(:group_2) { create(:group, organization: organization_2) }

          let_it_be(:first_replicable_and_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, organization: organization_1))
          end

          let_it_be(:second_replicable_and_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, organization: organization_1))
          end

          let_it_be(:third_replicable_on_object_storage_and_in_selective_sync) do
            create(:geo_#{@file_name}, :remote_store, parent_model: create(:#{@parent_model_factory_name}, organization: organization_1))
          end

          let_it_be(:last_replicable_and_not_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, organization: organization_2))
          end
        RUBY
      end

      def selective_sync_fixtures_for_namespace_id
        <<~RUBY
          let_it_be(:group_1) { create(:group, organization: create(:organization)) }
          let_it_be(:group_2) { create(:group, organization: create(:organization)) }
          let_it_be(:nested_group_1) { create(:group, parent: group_1) }

          let_it_be(:first_replicable_and_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, group: group_1))
          end

          let_it_be(:second_replicable_and_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, group: nested_group_1))
          end

          let_it_be(:third_replicable_on_object_storage_and_in_selective_sync) do
            create(:geo_#{@file_name}, :remote_store, parent_model: create(:#{@parent_model_factory_name}, group: group_1))
          end

          let_it_be(:last_replicable_and_not_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, group: group_2))
          end
        RUBY
      end

      def selective_sync_fixtures_for_project_id
        <<~RUBY
          let_it_be(:group_1) { create(:group, organization: create(:organization)) }
          let_it_be(:group_2) { create(:group, organization: create(:organization)) }
          let_it_be(:nested_group_1) { create(:group, parent: group_1) }
          let_it_be(:project_1) { create(:project, group: group_1) }
          let_it_be(:project_2) { create(:project, group: nested_group_1) }
          let_it_be(:project_3) { create(:project, group: group_2) }

          let_it_be(:first_replicable_and_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, project: project_1))
          end

          let_it_be(:second_replicable_and_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, project: project_2))
          end

          let_it_be(:third_replicable_on_object_storage_and_in_selective_sync) do
            create(:geo_#{@file_name}, :remote_store, parent_model: create(:#{@parent_model_factory_name}, project: project_1))
          end

          let_it_be(:last_replicable_and_not_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, project: project_3))
          end
        RUBY
      end

      def selective_sync_fixtures_for_uploaded_by_user_id
        <<~RUBY
          let_it_be(:organization_1) { create(:organization) }
          let_it_be(:organization_2) { create(:organization) }
          let_it_be(:group_1) { create(:group, organization: organization_1) }
          let_it_be(:group_2) { create(:group, organization: organization_2) }
          let_it_be(:user_1) { create(:user, organizations: [organization_1]) }
          let_it_be(:user_2) { create(:user, organizations: [organization_2]) }

          before_all do
            group_1.add_developer(user_1)
            group_2.add_developer(user_2)
          end

          let_it_be(:first_replicable_and_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, user: user_1))
          end

          let_it_be(:second_replicable_and_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, user: user_1))
          end

          let_it_be(:third_replicable_on_object_storage_and_in_selective_sync) do
            create(:geo_#{@file_name}, :remote_store, parent_model: create(:#{@parent_model_factory_name}, user: user_1))
          end

          let_it_be(:last_replicable_and_not_in_selective_sync) do
            create(:geo_#{@file_name}, parent_model: create(:#{@parent_model_factory_name}, user: user_2))
          end
        RUBY
      end
    end
  end
end
