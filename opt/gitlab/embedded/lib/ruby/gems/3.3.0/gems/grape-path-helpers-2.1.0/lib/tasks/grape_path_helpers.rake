# frozen_string_literal: true

namespace :grape do
  desc 'Print route helper methods.'
  task path_helpers: :environment do
    GrapePathHelpers::RouteDisplayer.new.display
  end
end
