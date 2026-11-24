# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      class HooksExecution < AbstractTask
        def execute
          SecApplicationRecord.current_transaction.after_commit do
            new_vulnerabilities.each do |vulnerability|
              vulnerability.execute_hooks
              vulnerability.trigger_false_positive_detection
            end
          end
        end

        private

        def new_vulnerabilities
          new_finding_maps.map(&:vulnerability_id)
                          .then { |ids| Vulnerability.id_in(ids).with_projects }
        end

        def new_finding_maps
          finding_maps.select { |map| map.new_record && eligible_context?(map) }
        end

        def eligible_context?(map)
          context = map.tracked_context
          return true if context.nil? || context.is_default?

          return false unless context.tracked?

          # Only the SAST and Secrets FP workers read code at the finding's ref.
          case map.report_finding.report_type.to_s
          when 'sast'
            sast_non_default_allowed?(context.project)
          when 'secret_detection'
            secrets_non_default_allowed?(context.project)
          else
            false
          end
        end

        # CVS ingestion passes a nil pipeline and can span many projects.
        def sast_non_default_allowed?(project)
          strong_memoize_with(:sast_non_default_allowed, project.id) do
            ::Vulnerability.fp_detection_non_default_branches_enabled?(project)
          end
        end

        def secrets_non_default_allowed?(project)
          strong_memoize_with(:secrets_non_default_allowed, project.id) do
            ::Vulnerability.secrets_fp_detection_non_default_branches_enabled?(project)
          end
        end
      end
    end
  end
end
