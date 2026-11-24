# frozen_string_literal: true

module Authz
  module GranularScopes
    # Picks the organization for a token from its scopes. Each scope takes the token's
    # organization, which must match its namespace's (GranularScope#organization_match).
    class OrganizationResolver
      MultipleOrganizationsError = Class.new(StandardError)

      # @param granular_scopes [Array<Authz::GranularScope>] unsaved scopes, as Builder returns them
      # @param default [Organizations::Organization] used when no scope has a namespace
      def initialize(granular_scopes, default:)
        @granular_scopes = granular_scopes
        @default = default
      end

      # @return [Organizations::Organization]
      # @raise [MultipleOrganizationsError] when the scopes' namespaces are in different organizations
      def organization
        organization_ids = granular_scopes.filter_map { |scope| scope.namespace&.organization_id }.uniq

        if organization_ids.size > 1
          raise MultipleOrganizationsError, 'Granular scopes must belong to a single organization'
        end

        return default if organization_ids.empty? || organization_ids.first == default.id

        ::Organizations::Organization.find(organization_ids.first)
      end

      private

      attr_reader :granular_scopes, :default
    end
  end
end
