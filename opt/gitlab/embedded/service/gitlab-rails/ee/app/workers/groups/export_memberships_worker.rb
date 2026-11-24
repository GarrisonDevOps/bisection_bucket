# frozen_string_literal: true

# rubocop:disable Scalability/IdempotentWorker -- Worker triggers email so cannot be considered idempotent.
module Groups
  class ExportMembershipsWorker < ::Members::Groups::BaseMembershipsExportWorker
    private

    def process_import
      Namespaces::Export::LimitedDataService.new(container: @group, current_user: @current_user).execute
    end
  end
end
# rubocop:enable Scalability/IdempotentWorker
