# frozen_string_literal: true

module Integrations
  module SlackEvents
    class AppMentionedService
      include Gitlab::Utils::StrongMemoize
      include Gitlab::InternalEventsTracking

      DUO_SLACK_DOCS_URL = 'https://docs.gitlab.com/user/project/integrations/gitlab_slack_application/#gitlab-duo'

      NO_ACCESS_MESSAGES = {
        experiment_features_disabled: 'This feature requires experiment and beta GitLab Duo features to be turned on. ',
        no_duo_seat: 'This feature requires GitLab Duo Agent Platform. ',
        externally_shared_channel: 'GitLab Duo is not available in channels shared with external organizations. '
      }.freeze

      def initialize(params)
        @params = params.with_indifferent_access
        @slack_event = (@params[:event] || {}).with_indifferent_access
        @slack_workspace_id = @params[:team_id]
        @slack_user_id = slack_event[:user]
        @channel_id = slack_event[:channel]
        @message_ts = slack_event[:ts]
        @thread_ts = slack_event[:thread_ts] || slack_event[:ts]
      end

      def execute
        return ServiceResponse.error(message: 'Missing Slack event data') unless valid_event?

        unless slack_installation
          Gitlab::IntegrationsLogger.info(
            slack_user_id: slack_user_id,
            slack_workspace_id: slack_workspace_id,
            message: 'SlackInstallation record has no bot token'
          )

          return ServiceResponse.success
        end

        # Checked before the user lookup, so external users get no account-linking prompt either.
        if externally_shared_channel?
          block_mention(nil, :externally_shared_channel)
          return ServiceResponse.success
        end

        gitlab_user = slack_gitlab_user_connection&.user

        unless gitlab_user
          track_blocked_mention(nil, 'user_not_linked')
          ensure_user_linked
          slack_api.add_reaction(channel: channel_id, name: 'lock', timestamp: message_ts)
          return ServiceResponse.success
        end

        unless Ability.allowed?(gitlab_user, :use_slash_commands)
          track_blocked_mention(gitlab_user, 'no_permission')
          return ServiceResponse.success
        end

        trigger_duo_flow(gitlab_user)

        ServiceResponse.success
      end

      private

      attr_reader :params, :slack_event, :slack_workspace_id, :slack_user_id, :channel_id, :message_ts, :thread_ts

      def valid_event?
        slack_workspace_id.present? && slack_user_id.present? && channel_id.present? && thread_ts.present?
      end

      # Fails closed: Slack documents the flag on every event callback, but older events arrived without it.
      def externally_shared_channel?
        params[:is_ext_shared_channel] != false
      end

      def track_blocked_mention(gitlab_user, reason)
        Gitlab::InternalEvents.with_batched_redis_writes do
          track_internal_event('receive_slack_duo_mention', user: gitlab_user)
          track_block_event(gitlab_user, reason)
        end
      end

      # Standalone block event for paths where receive_slack_duo_mention has
      # already fired, such as flow trigger failures in EE.
      def track_block_event(gitlab_user, reason)
        track_internal_event(
          'block_slack_duo_mention',
          user: gitlab_user,
          additional_properties: { property: reason }
        )
      end

      # Returns the thread_ts to use for ephemeral messages, so they appear
      # inside the thread when the bot was mentioned within one. When the
      # mention is at the channel root (thread_ts == message_ts), returns nil
      # so the ephemeral is posted at the channel root (existing behaviour).
      def ephemeral_thread_ts
        thread_ts != message_ts ? thread_ts : nil
      end

      def block_mention(gitlab_user, reason)
        track_blocked_mention(gitlab_user, reason.to_s)
        post_no_access_message("#{NO_ACCESS_MESSAGES.fetch(reason)}For more information, see #{DUO_SLACK_DOCS_URL}")
      end

      def post_no_access_message(text)
        slack_api.add_reaction(channel: channel_id, name: 'lock', timestamp: message_ts)
        slack_api.post_ephemeral(
          channel: channel_id, user: slack_user_id, text: text, thread_ts: ephemeral_thread_ts
        )
      end

      def slack_installation
        SlackIntegration.with_bot.find_by_team_id(slack_workspace_id)
      end
      strong_memoize_attr :slack_installation

      def slack_api
        @slack_api ||= ::Slack::API.new(slack_installation)
      end

      def slack_gitlab_user_connection
        ChatNames::FindUserService.new(slack_workspace_id, slack_user_id).execute
      end
      strong_memoize_attr :slack_gitlab_user_connection

      # Overridden in EE, which runs GitLab Duo. FOSS has none, so it refuses with the experiment setting,
      # which EE also answers through super.
      def trigger_duo_flow(gitlab_user)
        block_mention(gitlab_user, :experiment_features_disabled)
      end

      def ensure_user_linked
        url = ChatNames::AuthorizeUserService.new(authorize_params).execute
        return unless url

        presenter = ::Gitlab::SlashCommands::Presenters::Access.new(url)
        slack_api.post_ephemeral(
          channel: channel_id,
          user: slack_user_id,
          text: presenter.authorize_for_mention[:text],
          thread_ts: ephemeral_thread_ts
        )
      rescue *Gitlab::HTTP::HTTP_ERRORS => e
        Gitlab::ErrorTracking.track_exception(e, slack_workspace_id: slack_workspace_id)
      end

      def authorize_params
        {
          team_id: slack_workspace_id,
          team_domain: team_domain,
          user_id: slack_user_id,
          user_name: slack_event[:user]
        }
      end

      def team_domain
        return params[:team_domain] if params[:team_domain]

        slack_installation.team_name
      end
    end
  end
end

Integrations::SlackEvents::AppMentionedService.prepend_mod
