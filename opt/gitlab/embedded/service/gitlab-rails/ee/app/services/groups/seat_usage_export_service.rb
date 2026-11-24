# frozen_string_literal: true

module Groups
  class SeatUsageExportService
    include Gitlab::Allowable

    def self.execute(group, user)
      new(group, user).execute
    end

    def initialize(group, user)
      @group = group
      @current_user = user
    end

    def execute
      return insufficient_permissions unless can?(current_user, :admin_group_member, group)

      ServiceResponse.success(payload: csv_builder.render)
    rescue StandardError => e
      Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
      ServiceResponse.error(message: 'Failed to generate export')
    end

    private

    attr_reader :group, :current_user

    def insufficient_permissions
      ServiceResponse.error(message: 'Insufficient permissions to generate export')
    end

    def csv_builder
      @csv_builder = CsvBuilder::Stream.new(data, header_to_value_hash)
    end

    def data
      result = BilledUsersFinder.new(group, order_by: 'id_asc').execute
      result[:users] || User.none
    end

    def export_private_email?(user)
      current_user.can_admin_all_resources? || user.enterprise_user_of_group?(group)
    end

    def header_to_value_hash
      {
        'Id' => 'id',
        'Name' => 'name',
        'Username' => 'username',
        'Email' => ->(user) { export_private_email?(user) ? user.email : user.public_email.presence },
        'State' => 'state',
        'Last GitLab activity' => ->(user) { user&.last_active_at&.iso8601 },
        'Last login' => ->(user) { user&.last_sign_in_at&.iso8601 }
      }
    end
  end
end
