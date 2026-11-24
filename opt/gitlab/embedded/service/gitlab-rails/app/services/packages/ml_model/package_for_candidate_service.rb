# frozen_string_literal: true

module Packages
  module MlModel
    class PackageForCandidateService < ::Packages::CreatePackageService
      def execute
        candidate = params[:candidate]

        return unless candidate

        package = find_or_create_candidate_package!(candidate)

        candidate.update!(package: package) if candidate.package_id != package.id

        package
      end

      private

      # Must not run inside a transaction: the retry needs a usable connection after RecordNotUnique.
      def find_or_create_candidate_package!(candidate)
        attempts = 0

        begin
          attempts += 1

          find_or_create_package!(
            ::Packages::MlModel::Package,
            name: candidate.package_name,
            version: candidate.package_version
          )
        rescue ActiveRecord::RecordNotUnique
          retry if attempts == 1

          raise
        rescue ActiveRecord::RecordInvalid => e
          retry if attempts == 1 && e.record.errors.of_kind?(:name, :taken)

          raise
        end
      end
    end
  end
end
