# frozen_string_literal: true

module API
  module Entities
    class ProjectDailyFetches < Grape::Entity
      expose :fetch_count, as: :count,
        documentation: { type: 'Integer', example: 3, desc: 'Number of fetches for the date.' }
      expose :date, documentation: { type: 'Date', example: '2022-01-01', desc: 'Date in ISO format (`YYYY-MM-DD`).' }
    end
  end
end
