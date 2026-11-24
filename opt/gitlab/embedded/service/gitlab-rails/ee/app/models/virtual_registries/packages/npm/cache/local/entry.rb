# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Npm
      module Cache
        module Local
          class Entry < ApplicationRecord
            self.primary_key = %i[group_id iid]

            belongs_to :group, optional: false
            belongs_to :upstream,
              class_name: 'VirtualRegistries::Packages::Npm::Upstream',
              inverse_of: :cache_local_entries,
              optional: false
            belongs_to :package_file,
              class_name: 'Packages::PackageFile',
              optional: false
          end
        end
      end
    end
  end
end
