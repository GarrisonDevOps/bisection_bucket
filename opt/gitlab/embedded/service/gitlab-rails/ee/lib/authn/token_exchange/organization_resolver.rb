# frozen_string_literal: true

module Authn
  module TokenExchange
    # Which organization a token speaks for, which decides the IAM principal it
    # resolves to. A supplied organization_id always wins, and is refused rather
    # than replaced when it does not match what the caller may use. Without one,
    # one order for every audience: the organization of the resource the token is
    # for, when there is one, then the account's own.
    #
    # The one exception is Artifact Registry, below.
    class OrganizationResolver
      # Raised when the caller belongs to more than one Artifact Registry
      # organization, so there is nothing to infer. Refused rather than
      # guessed, since a token naming the wrong organization resolves to a
      # different principal in IAM and silently sees none of the caller's
      # roles. The message is shown to the caller.
      AmbiguousOrganizationError = Class.new(StandardError)

      # Raised when organization_id names an organization the caller cannot use
      # for this audience. Covers a missing one too, so the answer does not reveal
      # which organizations exist.
      OrganizationNotFoundError = Class.new(StandardError)

      # Interim exception, not part of the order above. Package clients (Maven,
      # npm, Docker) send a credential and nothing else, and the organization
      # that owns the account is the wrong answer once a group has moved into a
      # promoted organization: accounts stay owned by the default organization
      # and gain membership of the promoted one. So for these audiences it is
      # inferred from the caller's Artifact Registry memberships.
      #
      # Under the closed beta every Artifact Registry repository is private
      # (ADR-021), so a caller can only reach artifacts in an organization they
      # hold a role in, which makes the single Artifact Registry organization
      # they belong to the one they must mean. That reasoning stops holding the
      # day public visibility exists, and this should be revisited then.
      #
      # A caller in several of them names one with organization_id. Inference
      # stays for clients that cannot send it, see
      # https://gitlab.com/gitlab-org/ops/artifact-registry/-/work_items/977.
      INFERRING_AUDIENCES = %w[gitlab-artifact-registry].freeze

      def initialize(user, audience:, resource_organization: nil, organization_id: nil)
        @user = user
        @audience = audience
        @resource_organization = resource_organization
        @organization_id = organization_id
      end

      def execute
        return named_organization if @organization_id

        @resource_organization || inferred_organization || own_organization
      end

      private

      # Only an organization the order above could have picked is accepted, so
      # naming any other one is refused rather than silently swapped.
      def named_organization
        organization =
          if @resource_organization
            @resource_organization
          elsif inferring?
            ::ArtifactRegistry::NamespaceMapping.for_member(@user).for_organization_id(@organization_id).first
              &.organization
          else
            own_organization
          end

        raise OrganizationNotFoundError unless organization&.id == @organization_id

        organization
      end

      def inferring?
        INFERRING_AUDIENCES.include?(@audience)
      end

      def inferred_organization
        return unless inferring?

        # Two is enough to tell "exactly one" from "more than one" without
        # loading every organization the caller belongs to.
        candidates = ::ArtifactRegistry::NamespaceMapping.for_member(@user).limit(2).map(&:organization)

        if candidates.size > 1
          raise AmbiguousOrganizationError,
            _('Your account belongs to more than one organization with Artifact Registry. ' \
              'Pass organization_id to choose one.')
        end

        candidates.first
      end

      # The default for every audience: with no resource organization and nothing
      # inferred, the token speaks for the organization that owns the account.
      # rubocop:disable Gitlab/AvoidUserOrganization -- the account's own organization is the default by design
      def own_organization
        @user.organization
      end
      # rubocop:enable Gitlab/AvoidUserOrganization
    end
  end
end
