# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsDuoFeaturesEnabledMetric < DatabaseMetric
          operation :count

          relation { ::ProjectSetting.where(duo_features_enabled: true) }

          start { ::ProjectSetting.minimum(:project_id) }
          finish { ::ProjectSetting.maximum(:project_id) }
        end
      end
    end
  end
end
