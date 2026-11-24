# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      # A Domain names one risk area in a merge request: authorization,
      # authentication, database migration, API contract, or credentials.
      # The domain catalog is the vocabulary sent to the risk classification
      # flow, which answers one claim per domain. The score weights that claim
      # by the domain's severity.
      #
      # Domains carry no file paths. Path matching is a separate, later layer
      # keyed to these same names. A domain is worth asking about whether or
      # not paths are configured for it, which is what lets this run on a
      # project whose layout we do not know.
      #
      # Candidate domains left out of phase one. Suggestions, not commitments.
      #
      # Security: SSRF and outbound requests (OWASP A10), input validation and injection sinks,
      # deserialization, path traversal, file uploads, CORS/CSP/security headers, webhook
      # signature verification, rate limiting, sandboxing of untrusted code, audit logging (OWASP A09).
      #
      # Data: cascade deletes and purges, personal data handling (GDPR, HIPAA), retention and
      # erasure, data residency, tenant-scoped caching, search indexing, backup and restore.
      # Money and contracts, mostly for customer projects rather than this repository: payments
      # (PCI DSS), billing, metering, quotas, licensing and entitlement, tax calculation.
      #
      # Delivery and supply chain: CI/CD pipeline definitions, build and release tooling (SLSA),
      # dependency manifests and lockfiles (OWASP A06), container and base images (NIST 800-190),
      # infrastructure as code, deployment and runtime config, artifact signing, scanner
      # configuration and finding suppressions.
      #
      # Availability and operations: background workers and queues, scheduled tasks, concurrency,
      # locking and transactions, idempotency and retries, observability, timeouts, circuit breakers.
      # Compatibility beyond REST and GraphQL: protobuf and gRPC schemas, event and message
      # schemas, SDK public interfaces, deprecation and removal paths.
      #
      # Governance, safety and AI: prompts and model config (EU AI Act), agent tool permissions,
      # content moderation, accessibility-critical UI code, safety-critical control logic
      # (IEC 62304), compliance control implementations, export control.
      #
      # Likely next addition: database_performance, for finders and model scopes.
      class Domain
        include ActiveRecord::FixedItemsModel::Model
        include Domains::Registry

        auto_generate_ids!

        SEVERITIES = %w[high critical].freeze

        attribute :name, :string
        attribute :severity, :string
        attribute :description, :string

        validates :name, presence: true
        validates :severity, presence: true, inclusion: { in: SEVERITIES }
        validates :description, presence: true

        # Append new domains at the end: auto_generate_ids! assigns ids by
        # position, so reordering these silently remaps every existing id.
        register_domain(Domains::Authorization)
        register_domain(Domains::Authentication)
        register_domain(Domains::DatabaseMigration)
        register_domain(Domains::ApiContract)
        register_domain(Domains::CredentialsCrypto)

        class << self
          def fixed_items
            registered_domains.map(&:configuration)
          end

          def description_for(name)
            find_by(name: name)&.description || name
          end
        end

        def description
          msgid = super
          return if msgid.blank?

          s_(msgid)
        end
      end
    end
  end
end
