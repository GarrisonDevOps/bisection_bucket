# frozen_string_literal: true

module API
  module Entities
    class GitlabLicenseWithActiveUsers < ::API::Entities::GitlabLicense
      expose :active_users, documentation: { type: 'Integer' } do |license, _options|
        license.daily_billable_users_count
      end
    end
  end
end
