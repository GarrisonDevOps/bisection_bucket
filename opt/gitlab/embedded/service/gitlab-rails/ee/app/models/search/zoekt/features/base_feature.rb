# frozen_string_literal: true

module Search
  module Zoekt
    module Features
      class BaseFeature
        class_attribute :minimum_schema_version,
          instance_reader: true, instance_writer: false
        class_attribute :globally_available_cache_duration,
          instance_reader: true, instance_writer: false, default: 1.day
        class_attribute :project_search_cache_duration,
          instance_reader: true, instance_writer: false, default: 10.minutes
        class_attribute :group_search_cache_duration,
          instance_reader: true, instance_writer: false, default: 10.minutes
        class_attribute :global_search_cache_duration,
          instance_reader: true, instance_writer: false, default: 10.minutes

        def self.available?(user = nil, project_id: nil, group_id: nil)
          new(user, project_id: project_id, group_id: group_id).available?
        end

        attr_reader :user, :project_id, :group_id, :cache_key

        def initialize(user, project_id: nil, group_id: nil)
          raise NotImplementedError, "#{self.class} must define minimum_schema_version" unless minimum_schema_version

          @user = user
          @project_id = project_id
          @group_id = group_id
          @cache_key = set_cache_key(project_id: project_id, group_id: group_id)
        end

        def available?
          return false unless preflight_checks_passed?

          # If the feature is globally available, we can skip further checks
          return true if Rails.cache.read(globally_available_cache_key) == true

          if project_id
            enabled_for_project_search?
          elsif group_id
            enabled_for_group_search?
          else
            enabled_for_global_search?.tap do |globally_available|
              if globally_available
                # Cache true result for a long time so we don't have to keep checking
                Rails.cache.write(globally_available_cache_key, true, expires_in: globally_available_cache_duration)
              end
            end
          end
        end

        private

        def preflight_checks_passed?
          true
        end

        def enabled_for_project_search?
          Rails.cache.fetch(cache_key, expires_in: project_search_cache_duration) do
            ::Search::Zoekt::Repository
              .for_project_id(project_id)
              .minimum_schema_version.to_i >= minimum_schema_version
          end
        end

        def enabled_for_group_search?
          return false unless namespace.present?

          znp = ::Search::Zoekt::EnabledNamespace.for_root_namespace_id(namespace.root_ancestor.id).first
          return false unless znp.present?

          Rails.cache.fetch(cache_key, expires_in: group_search_cache_duration) do
            ::Search::Zoekt::Repository
              .for_zoekt_indices(znp.indices)
              .minimum_schema_version.to_i >= minimum_schema_version
          end
        end

        def namespace
          @namespace ||= Namespace.find_by(id: group_id) if group_id
        end

        def enabled_for_global_search?
          Rails.cache.fetch(cache_key, expires_in: global_search_cache_duration) do
            ::Search::Zoekt::Repository.minimum_schema_version.to_i >= minimum_schema_version
          end
        end

        def set_cache_key(project_id: nil, group_id: nil)
          if project_id
            project_searchable_cache_key(project_id)
          elsif group_id
            group_searchable_cache_key(group_id)
          else
            global_searchable_cache_key
          end
        end

        def globally_available_cache_key
          [self.class.name.demodulize.underscore, :globally_available]
        end

        def project_searchable_cache_key(project_id)
          [self.class.name.demodulize.underscore, :project, project_id]
        end

        def group_searchable_cache_key(group_id)
          [self.class.name.demodulize.underscore, :group, group_id]
        end

        def global_searchable_cache_key
          [self.class.name.demodulize.underscore, :global]
        end
      end
    end
  end
end
