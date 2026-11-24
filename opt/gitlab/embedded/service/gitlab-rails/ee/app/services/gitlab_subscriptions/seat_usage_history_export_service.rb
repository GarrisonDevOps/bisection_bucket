# frozen_string_literal: true

module GitlabSubscriptions
  class SeatUsageHistoryExportService < ExportCsv::BaseService
    TARGET_FILESIZE = 1.megabyte

    private

    attr_reader :historical_data_relation

    def header_to_value_hash
      {
        'History entry date' => 'created_at',
        'Subscription updated at' => 'gitlab_subscription_updated_at',
        'Start date' => 'start_date',
        'End date' => 'end_date',
        'Seats purchased' => 'seats',
        'Seats in use' => 'seats_in_use',
        'Max seats used' => 'max_seats_used',
        'Change Type' => 'change_type'
      }
    end
  end
end
