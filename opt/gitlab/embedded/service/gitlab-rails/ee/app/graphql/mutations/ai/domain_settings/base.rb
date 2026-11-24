# frozen_string_literal: true

module Mutations
  module Ai
    module DomainSettings
      # rubocop: disable GraphQL/GraphqlName -- It's an abstraction not meant to be used in the schema
      class Base < BaseMutation
        VALID_DOMAIN_REGEX = /\A(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\z/

        argument :action, ::Types::Ai::DomainSettingActionEnum,
          required: true,
          description: 'Action to perform on the domain list.'

        argument :domain_setting_type, ::Types::Ai::DomainSettingTypeEnum,
          required: true,
          description: 'Type of domain setting to update.'

        argument :domains, [GraphQL::Types::String],
          required: true,
          description: 'List of domains to add or remove.'

        field :added_domains, [GraphQL::Types::String],
          null: true,
          description: 'Domains that were added in the operation.'

        field :removed_domains, [GraphQL::Types::String],
          null: true,
          description: 'Domains that were removed in the operation.'

        private

        def adding?(action)
          action == 'add'
        end

        def allowing?(domain_setting_type)
          domain_setting_type == 'allowed'
        end

        def valid_domain?(domain)
          VALID_DOMAIN_REGEX.match?(domain)
        end

        def normalize_domains(domains)
          domains.map(&:downcase)
        end

        def validate_domains(action, domains)
          return unless adding?(action)

          invalid = domains.reject { |d| valid_domain?(d) }
          return unless invalid.any?

          error_result(invalid.map { |d| "#{d} is not a valid domain" })
        end

        def compute_updated_domains(current_domains, action, domains)
          adding?(action) ? (current_domains + domains).uniq : current_domains - domains
        end

        def build_result(action, current_domains, final_domains)
          adding = adding?(action)
          { added_domains: adding ? final_domains - current_domains : nil,
            removed_domains: adding ? nil : current_domains - final_domains,
            errors: [] }
        end

        def error_result(errors)
          { added_domains: nil, removed_domains: nil, errors: errors }
        end
      end
      # rubocop: enable GraphQL/GraphqlName
    end
  end
end
