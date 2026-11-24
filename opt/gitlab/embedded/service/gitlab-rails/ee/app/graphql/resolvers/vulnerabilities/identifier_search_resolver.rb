# frozen_string_literal: true

module Resolvers
  module Vulnerabilities
    class IdentifierSearchResolver < BaseResolver
      include VulnerabilityFilterable
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ::Security::GroupIdentifierSearch

      authorize :read_security_resource

      type [GraphQL::Types::String], null: false

      argument :name, GraphQL::Types::String,
        required: true,
        description: 'Search identifier by name. Substring or partial match search is supported and ' \
          'argument should be greater than 3 characters.'

      def resolve(**args)
        authorize!

        return unless args[:name].present?

        validate_args(args)

        return search_from_es(args) if advanced_vuln_mgmt_available?

        search_by_identifier_allowed_on_db!(vulnerable: object)

        if object.is_a?(::Project)
          ::Vulnerabilities::Identifier.search_identifier_name(
            object.project_id, args[:name])
        elsif object.is_a?(::Group)
          ::Vulnerabilities::Identifier.search_identifier_name_in_group(
            object, args[:name])
        end
      end

      private

      def validate_args(args)
        return unless args[:name].length < 3

        raise ::Gitlab::Graphql::Errors::ArgumentError,
          'Name should be greater than 3 characters.'
      end

      def authorize!
        Ability.allowed?(context[:current_user], :read_security_resource, object) ||
          raise_resource_not_available_error!
      end

      def search_from_es(args)
        ::Search::AdvancedFinders::Security::Vulnerability::IdentifierNamesFinder.new(
          object,
          { partial_identifier_name: args[:name] }).execute
      end
    end
  end
end
