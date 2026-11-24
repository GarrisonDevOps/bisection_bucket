# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Concerns
        module XrayContext
          include Gitlab::Utils::StrongMemoize

          MAX_LIBRARIES = 300

          def libraries
            return [] unless xray_report

            xray_report.libs.map { |l| l['name'] }.first(MAX_LIBRARIES) # rubocop:disable Rails/Pluck -- libs is an array
          end
          strong_memoize_attr :libraries

          private

          def xray_report
            ::Projects::XrayReport.for_project(project).for_lang(language.x_ray_lang).first
          end
          strong_memoize_attr :xray_report
        end
      end
    end
  end
end
