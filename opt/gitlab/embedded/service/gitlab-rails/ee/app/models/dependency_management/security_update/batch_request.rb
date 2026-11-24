# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # The requests for one lockfile, submitted as one workload and one merge request.
    class BatchRequest
      BRANCH_PREFIX = "#{Request::BRANCH_PREFIX}/batch".freeze
      MAX_PATH_SEGMENT_LENGTH = 100

      attr_reader :requests, :target_ref

      # One stable branch per lockfile, so a refresh reuses it. A path can hold 1,024 characters and a
      # source branch 255, so the readable part is cut short. A digest of the raw path keeps paths apart.
      def self.source_ref_for(package_manager, input_file_path)
        path = Request.sanitize_ref_segment(input_file_path.to_s).first(MAX_PATH_SEGMENT_LENGTH).chomp('-')
        digest = Digest::SHA256.hexdigest(input_file_path.to_s).first(8)

        "#{BRANCH_PREFIX}/#{package_manager}/#{path.presence || 'root'}-#{digest}"
      end

      def self.batch_branch?(branch)
        branch.to_s.start_with?("#{BRANCH_PREFIX}/")
      end

      def initialize(requests:, target_ref: nil)
        raise ArgumentError, 'requests are required' if requests.blank?

        keys = requests.map { |request| [request.sbom_occurrence.project_id, request.ecosystem, request.filepath.to_s] }
        raise ArgumentError, 'requests must share one project, package manager and lockfile' if keys.uniq.size > 1

        @requests = requests
        @target_ref = target_ref || requests.first.target_ref
      end

      def ecosystem
        requests.first.ecosystem
      end

      def filepath
        requests.first.filepath
      end

      def source_ref
        self.class.source_ref_for(ecosystem, filepath)
      end

      # Two occurrences of one package in a lockfile are one dependency to the updater.
      def dependency_names
        requests.map(&:dependency).uniq
      end

      def remediation_pairs
        requests.map do |request|
          { occurrence_id: request.sbom_occurrence.id, vulnerability_id: request.vulnerability.id }
        end
      end
    end
  end
end
