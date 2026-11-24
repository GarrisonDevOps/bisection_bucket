# frozen_string_literal: true

module API
  module Entities
    module Orbit
      class SkillFile < Grape::Entity
        expose(:path, documentation: { type: 'String', example: 'SKILL.md' }) { |skill_file| skill_file['path'] }
        expose(:sha256, documentation: { type: 'String', example: 'abc123' }) { |skill_file| skill_file['sha256'] }
        expose(:content, documentation: { type: 'String', example: '# Orbit skill' }) do |skill_file|
          skill_file['content']
        end
      end
    end
  end
end
