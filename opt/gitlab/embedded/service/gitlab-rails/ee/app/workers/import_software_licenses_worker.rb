# frozen_string_literal: true

class ImportSoftwareLicensesWorker # rubocop:disable Scalability/IdempotentWorker
  include ApplicationWorker

  data_consistency :always

  sidekiq_options retry: 3

  queue_namespace :cronjob
  feature_category :software_composition_analysis

  def perform; end
end
