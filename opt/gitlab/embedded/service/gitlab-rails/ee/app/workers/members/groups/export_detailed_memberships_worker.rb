# frozen_string_literal: true

# rubocop:disable Scalability/IdempotentWorker -- Worker triggers email so cannot be considered idempotent.
module Members
  module Groups
    class ExportDetailedMembershipsWorker < BaseMembershipsExportWorker
      private

      def process_import
        Namespaces::Export::DetailedDataService.new(container: @group, current_user: @current_user).execute
      end
    end
  end
end
# rubocop:enable Scalability/IdempotentWorker
