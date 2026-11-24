# frozen_string_literal: true

require_relative 'data_model/base'

module Gitlab
  module CloudConnector
    module DataModel
      autoload(:YamlDataLoader, 'gitlab/cloud_connector/data_model/yaml_data_loader')

      # Returns a hash of all data objects loaded from YAML files.
      def self.load_all(loader_class: YamlDataLoader)
        Base.subclasses.each_with_object({}) do |clazz, h|
          data_obj = loader_class.new(clazz).load_with_index!
          key = clazz.name.demodulize.pluralize.underscore.to_sym
          h[key] = data_obj.values.uniq.map(&:to_hash)
        end
      end

      class UnitPrimitive < Base
        has_and_belongs_to_many :backend_services
        has_and_belongs_to_many :add_ons
        has_and_belongs_to_many :license_types

        attr_reader :cut_off_date, :deprecated_by_url, :deprecation_message, :description, :documentation_url,
          :feature_category, :group, :introduced_by_url, :milestone, :min_gitlab_version,
          :min_gitlab_version_for_free_access, :name, :unit_primitive_issue_url, :alias_names

        # Whether the unit primitive is currently in its free-access period
        # (no cut-off date set, or cut-off date is in the future).
        def free_access?
          cut_off_date.nil? || cut_off_date.future?
        end
      end

      class Service < Base
        has_and_belongs_to_many :unit_primitives

        attr_reader :basic_unit_primitive, :description, :gitlab_realm, :name
      end

      class BackendService < Base
        attr_reader :description, :group, :jwt_aud, :name, :project_url
      end

      class LicenseType < Base
        attr_reader :description, :name
      end

      class AddOn < Base
        attr_reader :description, :name
      end
    end
  end
end
