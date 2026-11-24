# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Resolves the GitLab user behind an Anthropic Compliance API session.
      #
      # Email is the only identifier the two systems share, and attributing a
      # session to the wrong account would leak it into another customer's audit
      # log, so anything uncertain is dropped instead of guessed.
      #
      # Build one resolver per session list page and call #resolve per session.
      # Memberships are cached for that page only, so email, account and
      # membership changes take effect on the next page.
      class UserResolver
        # @param group [Group] the namespace the sessions are being ingested for
        def initialize(group:)
          @group = group
          @memberships = {}
        end

        # @param session [Hash] one entry from the Anthropic session list response
        # @return [User, nil] nil when the session must be dropped
        def resolve(session)
          session = session.to_h.with_indifferent_access
          email = session.dig(:user, :email_address)

          # Anthropic omits the email when the Claude account was deleted or left the
          # organization, which the customer cannot fix on the GitLab side.
          return drop(:no_anthropic_email, session) if email.blank?

          users = matching_users(email)

          return drop(:no_gitlab_user, session) if users.empty?
          # `by_any_email` unions without an ORDER BY, so with several matches
          # there is no stable answer for which account owns the session.
          return drop(:ambiguous_match, session, gitlab_user_ids: users.map(&:id)) if users.size > 1

          user = users.first
          return drop(:not_namespace_member, session) unless member?(user)

          user
        end

        private

        attr_reader :group

        # `confirmed: true` stops an unconfirmed claim on somebody else's address
        # from taking over that person's sessions.
        def matching_users(email)
          ::User.by_any_email(email, confirmed: true).to_a
        end

        # Starting from the user makes this independent of how many namespaces
        # exist, so one check per user covers every session in the run.
        def member?(user)
          return @memberships[user.id] if @memberships.key?(user.id)

          @memberships[user.id] = group.member_of_self_or_descendant?(user)
        end

        def drop(reason, session, **extra)
          ::Gitlab::AppJsonLogger.info(
            {
              ::Labkit::Fields::CLASS_NAME => self.class.name,
              ::Labkit::Fields::LOG_MESSAGE => 'Dropped Anthropic session',
              :drop_reason => reason,
              ::Labkit::Fields::GL_NAMESPACE_ID => group.id,
              :anthropic_session_id => session[:id],
              :anthropic_user_id => session.dig(:user, :id)
            }.merge(extra)
          )

          nil
        end
      end
    end
  end
end
