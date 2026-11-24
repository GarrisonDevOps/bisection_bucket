# frozen_string_literal: true

module Authn
  module TokenExchange
    # An audience POST /token_exchange can mint tokens for. Each modular service
    # joins by adding an entry to .all rather than a branch in the endpoint, so the
    # endpoint stays generic and iam-sts can take over the same contract. An entry
    # only declares what it is: name, lifetime, extra audiences and who may use it.
    # Which organization a token speaks for is not its business, see
    # OrganizationResolver.
    class Audience
      attr_reader :name, :max_ttl

      def self.all
        @all ||= [
          new(
            name: 'gitlab-artifact-registry',
            max_ttl: 12.hours.to_i,
            # Artifact Registry needs Relationships/Lookup API access.
            extra_audiences: [TokenIssuer::DATA_ACCESS_AUDIENCE]
          ),
          new(
            name: 'gitlab-autoflow',
            max_ttl: 12.hours.to_i,
            # The holder can start workflows in its organization's namespace, so only flagged users
            # may mint it, and not from CI jobs, which run as whoever started them. IAM delegation
            # replaces this: https://gitlab.com/gitlab-org/primitives/trigger/-/merge_requests/10
            enabled: ->(user) { Feature.enabled?(:token_exchange_autoflow_audience, user) },
            job_token_allowed: false
          )
        ].freeze
      end

      def self.find(name)
        all.find { |audience| audience.name == name }
      end

      def self.names
        all.map(&:name)
      end

      def initialize(name:, max_ttl:, extra_audiences: [], enabled: ->(_user) { true }, job_token_allowed: true)
        @name = name
        @max_ttl = max_ttl
        @extra_audiences = extra_audiences
        @enabled = enabled
        @job_token_allowed = job_token_allowed
      end

      # The `aud` claim: this audience plus any the service also needs.
      def audiences
        [name, *@extra_audiences]
      end

      # Whether this user may mint for the audience, typically a feature flag.
      def enabled?(user)
        @enabled.call(user)
      end

      # Whether a CI job may mint for it. A job runs as the user who started it.
      def job_token_allowed?
        @job_token_allowed
      end
    end
  end
end
