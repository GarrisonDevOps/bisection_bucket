# frozen_string_literal: true

module API
  module Entities
    module Orbit
      class SkillCollection < Grape::Entity
        expose :skills, using: ::API::Entities::Orbit::SkillSummary, documentation: { is_array: true } do |collection|
          collection['skills']
        end
        expose(:server_version, documentation: { type: 'String', example: '0.31.0' }) do |collection|
          collection['server_version']
        end
      end
    end
  end
end
