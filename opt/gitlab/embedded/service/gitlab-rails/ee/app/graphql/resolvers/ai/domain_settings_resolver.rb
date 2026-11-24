# frozen_string_literal: true

module Resolvers
  module Ai
    class DomainSettingsResolver < BaseResolver
      type GraphQL::Types::String.connection_type, null: true
      description 'Returns AI domain settings for the given scope.'

      argument :domain_setting_type, ::Types::Ai::DomainSettingTypeEnum,
        required: true,
        description: 'Type of domain setting to retrieve.'

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Filter domains by substring match.'

      def resolve(domain_setting_type:, search: nil)
        return unless can_read_settings?

        domains = fetch_domains(domain_setting_type)
        return domains unless search.present?

        domains.select { |domain| domain.downcase.include?(search.downcase) }
      end

      private

      def can_read_settings?
        if object.is_a?(::Namespace)
          object.root? && Ability.allowed?(current_user, :read_ai_domain_settings, object)
        else
          current_user&.can_admin_all_resources?
        end
      end

      def fetch_domains(domain_setting_type)
        if object.is_a?(::Namespace)
          fetch_namespace_domains(domain_setting_type)
        else
          fetch_instance_domains(domain_setting_type)
        end
      end

      def fetch_namespace_domains(domain_setting_type)
        case domain_setting_type
        when 'allowed' then object.ai_allowed_domains
        when 'denied' then object.ai_denied_domains
        end
      end

      def fetch_instance_domains(domain_setting_type)
        ai_settings = ::Ai::Setting.for_organization_read_only(::Current.organization)

        case domain_setting_type
        when 'allowed' then ai_settings.allowed_domains
        when 'denied' then ai_settings.denied_domains
        end
      end
    end
  end
end
