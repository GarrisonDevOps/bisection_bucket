# frozen_string_literal: true

module CloudConnector
  module Tokens
    class TokenIssuer
      def initialize(name_or_url:, subject:, realm:, active_add_ons:, ttl:, jwk:, extra_claims: {})
        @name_or_url = name_or_url
        @subject = subject
        @realm = realm
        @active_add_ons = active_add_ons
        @ttl = ttl
        @jwk = jwk
        @extra_claims = extra_claims
      end

      def token
        unit_primitives = available_unit_primitives
        backends = backends_for(unit_primitives)

        ::Gitlab::CloudConnector::JsonWebToken.new(
          issuer: name_or_url,
          audience: backends.map(&:jwt_aud),
          subject: subject,
          realm: realm,
          scopes: unit_primitives.map(&:name),
          ttl: ttl,
          extra_claims: extra_claims
        ).encode(jwk)
      end

      private

      attr_reader :name_or_url, :subject, :realm, :active_add_ons, :ttl, :jwk, :extra_claims

      def available_unit_primitives
        unit_primitives.select do |unit_primitive|
          up_addon_names = unit_primitive.add_ons.map(&:name)
          unit_primitive.free_access? || (active_add_ons & up_addon_names).any?
        end
      end

      def unit_primitives
        ::Gitlab::CloudConnector::DataModel::UnitPrimitive.all
      end

      def backends_for(unit_primitives)
        unit_primitives.flat_map(&:backend_services).uniq
      end
    end
  end
end
