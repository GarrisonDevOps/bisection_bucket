# frozen_string_literal: true

module AntiAbuse
  class NewAbuseReportWorker
    include ApplicationWorker

    feature_category :instance_resiliency

    data_consistency :delayed
    urgency :low

    idempotent!

    attr_reader :user, :reporter, :abuse_report

    def perform(abuse_report_id)
      @abuse_report = ::AbuseReport.find_by_id(abuse_report_id)
      return unless abuse_report&.category == 'spam'

      @reporter = abuse_report.reporter
      @user = abuse_report.user

      return unless user && reporter
      return unless reporter.gitlab_employee?
      return unless bannable_user?

      Users::AutoBanService.new(user: user, reason: abuse_report.category).execute!
      UserCustomAttribute.set_banned_by_abuse_report(abuse_report)

      log_event
    end

    private

    def bannable_user?
      return false unless user.active? && user.human?
      return false if user.gitlab_employee? || user.account_age_in_days > 7
      return false if user.belongs_to_paid_namespace?(exclude_trials: true) || user_owns_populated_namespaces?

      true
    end

    def user_owns_populated_namespaces?
      user.owned_groups.find { |group| group.users_count > 5 } # rubocop: disable Gitlab/NoFindInWorkers -- not ActiveRecordFind
    end

    def log_event
      Gitlab::AppLogger.info(
        message: "User ban",
        user_id: user.id,
        username: user.username,
        abuse_report_id: abuse_report.id,
        reason: "Automatic ban triggered by abuse report for #{abuse_report.category}."
      )
    end
  end
end
