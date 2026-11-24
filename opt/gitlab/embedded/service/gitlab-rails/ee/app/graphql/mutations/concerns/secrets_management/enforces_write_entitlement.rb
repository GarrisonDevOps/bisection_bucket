# frozen_string_literal: true

module SecretsManagement
  # A mutation opts in with:
  #
  #   include ::SecretsManagement::EnforcesWriteEntitlement
  #   enforces_write_entitlement_for :project_secret
  #
  # This hooks GraphQL-Ruby's `#ready?` to short-circuit an entitlement-denied
  # write with a structured `reason`, instead of letting `authorized_find!`
  # raise a generic `ResourceNotAvailable` error. `resolve` is untouched.
  module EnforcesWriteEntitlement
    extend ActiveSupport::Concern

    WRITE_DENIAL_MESSAGE = 'Secrets Manager access is restricted for this namespace.'

    # Abilities that surface Secrets Manager status regardless of entitlement,
    # used to gate who may learn `namespace`'s entitlement status at all.
    ENTITLEMENT_VISIBILITY_ABILITY = {
      ::Project => :read_project_secrets_manager_status,
      ::Group => :read_group_secrets_manager_status
    }.freeze

    included do
      field :reason,
        Types::SecretsManagement::WriteActionDenialReasonEnum,
        null: true,
        description: 'Reason the write was denied due to entitlement; null when not denied for that reason.',
        experiment: { milestone: '19.2' }

      class_attribute :entitlement_payload_key, instance_writer: false
      class_attribute :entitlement_find_by_key, instance_writer: false
    end

    class_methods do
      # `payload_key` is the payload field nil'd out on entitlement denial;
      # `find_by` is the `find_object` keyword argument (`:project_path`,
      # `:group_path`, or `:vulnerability_id`, where `find_object` returns the
      # vulnerability's project) used to look up the namespace to check entitlement for.
      # e.g. `enforces_write_entitlement_for :project_secret, find_by: :project_path`.
      def enforces_write_entitlement_for(payload_key, find_by:)
        self.entitlement_payload_key = payload_key
        self.entitlement_find_by_key = find_by
      end
    end

    def ready?(**args)
      denial = entitlement_write_denial_response(**args)
      return false, denial if denial

      super
    end

    private

    def entitlement_write_denial_response(**args)
      namespace = find_object(entitlement_find_by_key => args[entitlement_find_by_key])
      namespace = namespace.sync if namespace.respond_to?(:sync)

      # Authorizing first stops callers from driving CustomersDot lookups for
      # namespaces they cannot access; they fail at `authorized_find!` instead.
      authorize_first = Feature.enabled?(:secrets_manager_authorize_before_entitlement_lookup, current_user)
      return if authorize_first && !authorized_to_see_entitlement?(namespace)

      entitlement = entitlement_for(namespace)
      reason = entitlement&.write_action_denial_reason
      return unless reason
      return unless authorize_first || authorized_to_see_entitlement?(namespace)

      ::SecretsManagement::Entitlement::DenialTelemetry.track(
        entitlement: entitlement,
        surface: :graphql_mutation,
        namespace: root_namespace_for(namespace),
        user: current_user
      )

      { entitlement_payload_key => nil, errors: [WRITE_DENIAL_MESSAGE], reason: reason }
    end

    # `ready?` runs ahead of `authorized_find!`, so without this a caller with no
    # access to `namespace` could still learn its entitlement status.
    def authorized_to_see_entitlement?(namespace)
      ability = ENTITLEMENT_VISIBILITY_ABILITY[namespace.class]
      return false unless ability

      Ability.allowed?(current_user, ability, namespace)
    end

    # `namespace` is a Group or Project. Returns the resolved
    # `SecretsManagement::Entitlement`, or nil when namespace is nil (callers
    # then treat the write as permitted).
    def entitlement_for(namespace)
      return unless namespace

      ::SecretsManagement::Entitlement.for(root_namespace_for(namespace), user: current_user)
    end

    def root_namespace_for(namespace)
      ::SecretsManagement::Entitlement.root_namespace_for(namespace)
    end
  end
end
