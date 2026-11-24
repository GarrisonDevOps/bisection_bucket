# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Pipeline
        module Chain
          module CommandPolicy
            extend ActiveSupport::Concern

            prepended do
              condition(:ondemand_dast_scan, scope: :subject) do
                @subject.ondemand_dast_scan?
              end

              rule { ~ondemand_dast_scan }.prevent :create_on_demand_dast_scan
            end
          end
        end
      end
    end
  end
end
