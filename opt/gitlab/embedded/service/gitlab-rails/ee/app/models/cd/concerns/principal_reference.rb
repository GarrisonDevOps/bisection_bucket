# frozen_string_literal: true

module Cd
  module Concerns
    # Included by Cd::RolloutTransition (and intended for reuse by
    # Cd::DeploymentTransition once deployment creation, and therefore its
    # attribution, is designed -- see https://gitlab.com/gitlab-org/gitlab/-/merge_requests/247152).
    #
    # `principal` (and optionally `on_behalf_of`) are free-text identity
    # references of the form `"user:1234"`, deliberately polymorphic per the
    # CD Rails design (a principal may be a user, agent, policy, schedule, or
    # system) rather than a foreign key. This concern is the single place
    # that resolves that reference to a user id, so callers never parse the
    # string format themselves.
    module PrincipalReference
      extend ActiveSupport::Concern

      USER_PRINCIPAL_PATTERN = /\Auser:(\d+)\z/

      # The id of the user that acted, if any.
      #
      # `on_behalf_of` takes precedence over `principal`: it names the human
      # ultimately responsible for a composite-identity action (for example,
      # an automated workflow acting on behalf of the user who triggered it).
      # Returns nil for non-user principals (agent/policy/schedule/system),
      # or when there is nothing to resolve.
      def acting_user_id
        user_id_from(on_behalf_of) || user_id_from(principal)
      end

      # The id of the user identified by `principal`, if any.
      #
      # Unlike `acting_user_id`, this does not consider `on_behalf_of`: it
      # answers "who is the principal", not "who is ultimately responsible".
      def principal_user_id
        user_id_from(principal)
      end

      class_methods do
        # Batched: the acting user id of the earliest transition for each of
        # the given parent ids (a rollout_id or deployment_id), keyed by that
        # parent id. The earliest transition is the one written when the
        # parent was created (see Cd::Rollouts::CreateService), so this is
        # "who triggered it".
        #
        # Parents with no transitions yet, or whose earliest transition has
        # no resolvable user principal, are omitted -- mirroring
        # Cd::Deployment.last_deployed_at_by_service, so callers can
        # distinguish "no acting user" (absent) from any actual id.
        def first_acting_user_id_by(parent_ids, foreign_key)
          quoted_column = connection.quote_column_name(foreign_key)

          # DISTINCT ON returns exactly one (the earliest, per the ORDER BY)
          # row per parent id directly from Postgres, rather than loading
          # every transition for the given parents into Ruby and grouping
          # them there.
          where(foreign_key => parent_ids)
            .select("DISTINCT ON (#{quoted_column}) #{quoted_column}, principal, on_behalf_of")
            .order(Arel.sql("#{quoted_column}, created_at ASC, id ASC"))
            .filter_map do |transition|
              user_id = transition.acting_user_id

              [transition[foreign_key], user_id] if user_id
            end
            .to_h
        end
      end

      private

      def user_id_from(value)
        match = USER_PRINCIPAL_PATTERN.match(value.to_s)
        match && match[1].to_i
      end
    end
  end
end
