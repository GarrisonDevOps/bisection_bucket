# frozen_string_literal: true

require 'active_support/core_ext/enumerable'
require 'active_support/core_ext/object/blank'

module Gitlab
  module CloudConnector
    class AvailableServicesGenerator
      GITLAB_REALMS = %w[gitlab-com self-managed].freeze
      WRONG_GITLAB_REALM_MESSAGE = 'Wrong gitlab_realm. Please use one of the following: %s'

      def generate(gitlab_realm)
        raise WRONG_GITLAB_REALM_MESSAGE % GITLAB_REALMS.join(', ') unless GITLAB_REALMS.include?(gitlab_realm)

        {
          'services' => generate_services_config(gitlab_realm)
        }
      end

      private

      def generate_services_config(gitlab_realm)
        services_config = {}

        DataModel::Service.each do |service|
          # Skip generating config for services not supported within the provided gitlab_realm
          next if service.gitlab_realm && !service.gitlab_realm&.include?(gitlab_realm)

          service_config = generate_service_config(service.unit_primitives, service.basic_unit_primitive)

          # For self_hosted_models, override bundling to only include duo_enterprise
          if service.name == 'self_hosted_models'
            duo_enterprise_config = service_config['bundled_with']['duo_enterprise']
            service_config['bundled_with'] = { 'duo_enterprise' => duo_enterprise_config }
          end

          services_config[service.name] = service_config
        end

        # Generate a stand-alone service config for each unit primitive
        service_names = DataModel::Service.map(&:name)
        DataModel::UnitPrimitive.each do |unit_primitive|
          # Skip if we already processed the entity with the same name. We either:
          # - already generated the service config
          # - skipped if service is not supported in the provided gitlab_realm
          next if service_names.include?(unit_primitive.name)

          services_config[unit_primitive.name] = generate_service_config([unit_primitive])
        end

        services_config.sort.to_h
      end

      def generate_service_config(unit_primitives, basic_unit_primitive = nil)
        sample_primitive = unit_primitives.find { |up| up.name == basic_unit_primitive } if basic_unit_primitive
        sample_primitive ||= unit_primitives.first
        backend_service = sample_primitive&.backend_services&.first

        {
          'backend' => backend_service&.jwt_aud,
          'cut_off_date' => sample_primitive&.cut_off_date&.strftime('%Y-%m-%d %H:%M:%S UTC'),
          'min_gitlab_version' => sample_primitive&.min_gitlab_version,
          'min_gitlab_version_for_free_access' => sample_primitive&.min_gitlab_version_for_free_access,
          'bundled_with' => generate_bundled_config(unit_primitives),
          'license_types' => sample_primitive&.license_types&.map(&:name)
        }.compact_blank
      end

      def generate_bundled_config(unit_primitives)
        unit_primitives.each_with_object({}) do |primitive, bundled|
          target_groups = primitive.add_ons.any? ? primitive.add_ons.map(&:name) : ['_irrelevant']
          target_groups.each do |group_name|
            group_name = group_name.to_s
            bundled[group_name] ||= { 'unit_primitives' => [] }
            bundled[group_name]['unit_primitives'] << primitive.name
          end
        end
      end
    end
  end
end
