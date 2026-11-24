# frozen_string_literal: true

module API
  module Entities
    class GitlabLicense < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :plan, documentation: { type: 'String', example: 'silver' }
      expose :created_at, documentation: { type: 'DateTime', example: '2012-05-28T04:42:42-07:00' }
      expose :starts_at, documentation: { type: 'Date', example: '2018-01-27' }
      expose :expires_at, documentation: { type: 'Date', example: '2022-01-27' }
      expose :historical_max, documentation: { type: 'Integer', example: 300 }
      expose :maximum_user_count, documentation: { type: 'Integer', example: 300 }
      expose :licensee, documentation: { type: 'Hash', example: { 'Name' => 'John Doe1' } }
      expose :add_ons, documentation: { type: 'Hash',
                                        example: { 'GitLab_FileLocks' => 1, 'GitLab_Auditor_User' => 1 } }

      expose :expired?, as: :expired, documentation: { type: 'Boolean' }

      expose :overage, documentation: { type: 'Integer', example: 200,
                                        desc: 'Difference between the number of billable users and the number of ' \
                                          'licensed users. Calculated differently depending on whether the license ' \
                                          'has expired or not.' } do |license, options|
        license.expired? ? license.overage_with_historical_max : license.overage(options[:current_active_users_count])
      end

      expose :user_limit, documentation: { type: 'Integer', example: 200 } do |license, _options|
        license.restricted?(:active_user_count) ? license.restrictions[:active_user_count] : 0
      end
    end
  end
end
