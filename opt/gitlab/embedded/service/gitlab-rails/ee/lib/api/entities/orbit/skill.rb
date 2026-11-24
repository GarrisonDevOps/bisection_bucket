# frozen_string_literal: true

module API
  module Entities
    module Orbit
      class Skill < Grape::Entity
        expose(:name, documentation: { type: 'String', example: 'orbit' }) { |skill| skill['name'] }
        expose(:version, documentation: { type: 'String', example: '0.29.0' }) { |skill| skill['version'] }
        expose(:compatibility, documentation: { type: 'String', example: 'Orbit CLI' }) do |skill|
          skill['compatibility']
        end
        expose(:server_version, documentation: { type: 'String', example: '0.31.0' }) do |skill|
          skill['server_version']
        end
        expose :files, using: ::API::Entities::Orbit::SkillFile, documentation: { is_array: true } do |skill|
          skill['files']
        end
      end
    end
  end
end
