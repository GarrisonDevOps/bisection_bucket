# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module CiAction
      class Unknown < Base
        def config
          {
            generate_job_name_with_index(@action[:scan]) => {
              'script' => 'echo "Error during Scan execution: Invalid Scan type" && false',
              'allow_failure' => true
            }
          }
        end
      end
    end
  end
end
