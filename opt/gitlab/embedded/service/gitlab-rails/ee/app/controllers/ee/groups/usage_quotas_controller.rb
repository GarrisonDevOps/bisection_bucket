# frozen_string_literal: true

module EE
  module Groups
    module UsageQuotasController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        include OneTrustCSP
        include GoogleAnalyticsCSP

        feature_category :consumables_cost_management, [:subscription_history]
        feature_category :seat_cost_management, [:pending_members]

        before_action only: [:root] do
          push_frontend_feature_flag(:data_transfer_monitoring, group)
        end
      end

      def pending_members
        render_404 unless group.user_cap_available?
      end

      def subscription_history
        history_records = group.gitlab_subscription_histories

        respond_to do |format|
          format.csv do
            send_data(
              ::GitlabSubscriptions::SeatUsageHistoryExportService.new(history_records).csv_data,
              type: 'text/csv; charset=utf-8',
              filename: "seat-usage-history-#{group.path}-#{Date.today}.csv"
            )
          end
        end
      end
    end
  end
end
