# frozen_string_literal: true

module Mutations
  module Ai
    module DomainSettings
      class InstanceUpdate < Base
        graphql_name 'AiDomainSettingsInstanceUpdate'
        description 'Adds or removes domains from the allowed or denied list for flows running in a sandboxed ' \
          'environment.'

        authorize_granular_token permissions: :update_ai_domain_settings,
          boundary: :instance, boundary_type: :instance

        def resolve(action:, domain_setting_type:, domains:)
          return raise_resource_not_available_error! unless current_user&.can_admin_all_resources?

          validation_error = validate_domains(action, domains)
          return validation_error if validation_error

          domains = normalize_domains(domains)

          ai_settings = ::Ai::Setting.for_organization(::Current.organization)
          current_domains = instance_domains(ai_settings, domain_setting_type)
          updated_domains = compute_updated_domains(current_domains, action, domains)

          if ai_settings.update(domain_attr(domain_setting_type) => updated_domains)
            build_result(action, current_domains, instance_domains(ai_settings, domain_setting_type))
          else
            error_result(ai_settings.errors.full_messages)
          end
        end

        private

        def instance_domains(ai_settings, domain_setting_type)
          allowing?(domain_setting_type) ? ai_settings.allowed_domains : ai_settings.denied_domains
        end

        def domain_attr(domain_setting_type)
          allowing?(domain_setting_type) ? :allowed_domains : :denied_domains
        end
      end
    end
  end
end
