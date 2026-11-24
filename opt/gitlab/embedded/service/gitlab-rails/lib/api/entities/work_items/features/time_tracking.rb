# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class TimeTracking < Grape::Entity
          class HumanReadableAttributes < Grape::Entity
            expose :human_time_estimate, as: :time_estimate,
              documentation: {
                type: 'String', example: '3h 30m',
                desc: 'Time estimate in human-readable format, such as `3h 30m`. Null if the estimate is 0.'
              },
              expose_nil: true
            expose :human_total_time_spent, as: :total_time_spent,
              documentation: {
                type: 'String', example: '1h 15m',
                desc: 'Total time spent in human-readable format, such as `1h 15m`. Null if the total is 0.'
              },
              expose_nil: true do |feature|
              Gitlab::TimeTrackingFormatter.output(feature.timelogs.sum(&:time_spent))
            end
          end

          class Timelog < Grape::Entity
            expose :id,
              documentation: { type: 'Integer', example: 1, desc: 'ID of the time log.' }
            expose :spent_at,
              documentation: {
                type: 'DateTime', example: '2024-01-15T10:00:00.000Z',
                desc: 'When the time was spent. Defaults to when the time log was created if no date was given.'
              },
              expose_nil: true do |timelog|
                timelog.spent_at || timelog.created_at
              end
            expose :time_spent,
              documentation: {
                type: 'Integer', example: 3600,
                desc: 'Time logged, in seconds. Negative if the log subtracts time.'
              }
            expose :user,
              using: ::API::Entities::UserBasic,
              documentation: { type: 'Entities::UserBasic', desc: 'User who logged the time.' }
            expose :summary,
              documentation: {
                type: 'String', example: 'Reviewed MR', desc: 'Summary of the time log. Null if none was given.'
              },
              expose_nil: true
          end

          expose :time_estimate,
            documentation: {
              type: 'Integer', example: 12600, desc: 'Time estimate, in seconds. 0 if no estimate is set.'
            },
            expose_nil: true
          expose :total_time_spent,
            documentation: {
              type: 'Integer', example: 4500,
              desc: 'Total time spent, in seconds: the sum of `time_spent` across all `timelogs`.'
            },
            expose_nil: true do |feature|
            feature.timelogs.sum(&:time_spent)
          end
          expose :human_readable_attributes,
            using: ::API::Entities::WorkItems::Features::TimeTracking::HumanReadableAttributes,
            documentation: {
              type: 'Entities::WorkItems::Features::TimeTracking::HumanReadableAttributes',
              desc: 'Time estimate and total time spent in human-readable format. A day is 8 hours and a month ' \
                'is 20 days. Only hours are used if the instance limits time tracking units to hours.'
            },
            expose_nil: true do |feature|
              feature
            end
          expose :timelogs,
            using: ::API::Entities::WorkItems::Features::TimeTracking::Timelog,
            documentation: {
              type: 'Entities::WorkItems::Features::TimeTracking::Timelog', is_array: true,
              desc: 'All time logs of the work item, in no guaranteed order. Empty if no time is logged.'
            }
        end
      end
    end
  end
end
