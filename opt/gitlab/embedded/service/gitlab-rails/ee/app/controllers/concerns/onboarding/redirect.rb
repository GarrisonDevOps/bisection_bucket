# frozen_string_literal: true

module Onboarding
  module Redirect
    extend ActiveSupport::Concern

    included do
      with_options if: :user_onboarding? do
        # We will handle the 2fa setup after onboarding if it is needed
        skip_before_action :check_two_factor_requirement
        before_action :onboarding_redirect
      end
    end

    private

    def onboarding_redirect
      return unless valid_for_onboarding_redirect?(current_user.onboarding_status_step_url)

      redirect_to current_user.onboarding_status_step_url
    end

    def user_onboarding?
      ::Onboarding.user_onboarding_in_progress?(current_user)
    end

    def valid_for_onboarding_redirect?(path)
      return false unless path.present? && request.get?
      return false if welcome_and_already_completed?

      gitlab_url = Gitlab.config.gitlab.url
      normalized_path = path.sub(/\A#{Regexp.escape(gitlab_url)}/, '')

      normalized_path != request.fullpath && valid_referer?(path)
    end

    def welcome_and_already_completed?
      return false if ::Feature.disabled?(:stop_welcome_redirection, current_user)
      return false if ::Onboarding.migrating_to_unified_welcome?(current_user)

      step_url = current_user.onboarding_status_step_url
      return false unless step_url.present?

      if step_url.include?(users_sign_up_welcome_path) && ::Onboarding.completed_welcome_step?(current_user)
        message = 'User has already completed welcome step'

        # We are trying to figure out if there is an issue with database
        # freshness here and using redis will help narrow it down.
        # See https://gitlab.com/gitlab-org/gitlab/-/issues/520090
        unless ::Onboarding.user_onboarding_in_progress?(current_user, use_cache: true)
          message += ' and their onboarding has already been marked as completed in redis'
        end

        begin
          ::Gitlab::ErrorTracking.track_exception(
            ::Onboarding::StepUrlError.new(message),
            onboarding_status: current_user.onboarding_status.to_json,
            onboarding_in_progress: current_user.onboarding_in_progress,
            db_host: User.connection.load_balancer.host.host,
            # pg_wal_lsn_diff to tell if one is behind the other
            db_lsn: User.connection.load_balancer.host.database_replica_location
          )
        rescue NotImplementedError, NoMethodError
          # For non production SaaS instances like test/CI and staging as there is only a primary and no replicas.
          # database_replica_location throws NotImplementedError
          # User.connection.load_balancer.host.host throws NoMethodError
          nil
        end

        Onboarding::FinishService.new(current_user).execute
        return true
      end

      false
    end

    def valid_referer?(path)
      # do not redirect additional requests on the page
      # with current page as a referer
      return true if request.referer.blank?

      referer_path = URI(request.referer).path
      referer_path.nil? || path.exclude?(referer_path)
    end
  end
end
